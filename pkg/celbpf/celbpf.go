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
)

type Env struct{}

func Compile(celExpr string, labelPrefix string) (asm.Instructions, error) {
	source := cgCommon.NewTextSource(celExpr)
	parser, err := cgParser.NewParser()
	if err != nil {
		return nil, fmt.Errorf("failed initialize CEL parser: %w", err)
	}

	ast, errs := parser.Parse(source)
	if len(errs.GetErrors()) > 0 {
		return nil, fmt.Errorf("failed to parse CEL expresion %q: %s", celExpr, errs.ToDisplayString())
	}

	checkerEnv, err := newCheckerEnv()
	if err != nil {
		return nil, err
	}

	ast, errs = cgChecker.Check(ast, source, checkerEnv)
	if len(errs.GetErrors()) > 0 {
		return nil, fmt.Errorf("check failed on CEL expresion %q: %s", celExpr, errs.ToDisplayString())
	}

	compiler := newCompiler(ast, source, labelPrefix)
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

func CompileFn(fnName, celExpr string) (asm.Instructions, error) {
	insns, err := Compile(celExpr, fnName)
	if err != nil {
		return nil, fmt.Errorf("failed to compile CEL expression %q: %w", celExpr, err)
	}
	fnTy := btfCelExprTy(fnName)
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fnTy.Name), fnTy).WithSource(s{celExpr})
	return insns, nil
}
