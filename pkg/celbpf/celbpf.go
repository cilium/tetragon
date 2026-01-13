// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CEL -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	cgChecker "github.com/google/cel-go/checker"
	cgCommon "github.com/google/cel-go/common"
	cgParser "github.com/google/cel-go/parser"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
)

type Env struct{}

type ExprArg struct {
	GenTy     int
	ArgOffset int
}

// EnabledInBPF returns true if celbpf is supported in the BPF programs
func EnabledInBPF() bool {
	return config.EnableLargeProgs()
}

// Supported returns true if celbpf is supported at runtime
// NB: The cel_expr code uses bpf-to-bpf calls, so we need to detect whether mixing bpf-to-bpf calls
// and tail-calls is allowed.
// See: https://lore.kernel.org/bpf/20200829231925.GB31692@ranger.igk.intel.com/T/
func Supported() bool {
	return bpf.DetectMixBpfAndTailCalls()
}

func Compile(celExpr string, args []ExprArg, labelPrefix string) (asm.Instructions, error) {
	source := cgCommon.NewTextSource(celExpr)
	parser, err := cgParser.NewParser()
	if err != nil {
		return nil, fmt.Errorf("failed initialize CEL parser: %w", err)
	}

	ast, errs := parser.Parse(source)
	if len(errs.GetErrors()) > 0 {
		return nil, fmt.Errorf("failed to parse CEL expresion %q: %s", celExpr, errs.ToDisplayString())
	}

	eargs := make([]exprArg, 0, len(args))
	for i := range args {
		earg, err := newExprArg(args[i])
		if err != nil {
			return nil, fmt.Errorf("failed to convert argument %d: %w", i, err)
		}
		eargs = append(eargs, earg)
	}

	checkerEnv, err := newCheckerEnv(eargs)
	if err != nil {
		return nil, err
	}

	ast, errs = cgChecker.Check(ast, source, checkerEnv)
	if len(errs.GetErrors()) > 0 {
		return nil, fmt.Errorf("check failed on CEL expresion %q: %s", celExpr, errs.ToDisplayString())
	}

	compiler := newCompiler(ast, source, eargs, labelPrefix)
	return compiler.compile()
}

type s struct {
	s string
}

func (s s) String() string {
	return s.s
}

func btfCelExprTy(fnName string) *btf.Func {
	return &btf.Func{
		Name: fnName,
		Type: &btf.FuncProto{
			Return: &btf.Int{
				Name:     "s32",
				Size:     4,
				Encoding: btf.Signed,
			},
			Params: []btf.FuncParam{},
		},
		Linkage: btf.StaticFunc,
	}
}

func CompileEmptyFunction(fnName string) asm.Instructions {
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
	fnTy := btfCelExprTy(fnName)
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fnTy.Name), fnTy).WithSource(s{"default"})
	return insns
}

func CompileFn(fnName, celExpr string, args []ExprArg) (asm.Instructions, error) {
	insns, err := Compile(celExpr, args, fnName)
	if err != nil {
		return nil, fmt.Errorf("failed to compile CEL expression %q: %w", celExpr, err)
	}
	fnTy := btfCelExprTy(fnName)
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fnTy.Name), fnTy).WithSource(s{celExpr})
	return insns, nil
}
