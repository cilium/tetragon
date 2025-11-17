// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package selectors

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/tetragon/pkg/celbpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const (
	// maximum number of CelExpr functions supported in the datapath
	MaxCelExprFunctions = 8 // see bpf/process/cel_expr.h
)

func CelExprFuncName(idx int) string {
	return fmt.Sprintf("cel_expr_%d", idx)
}

// CelExprFunctions holds all the generated instructions for the CEL expressions
type CelExprFunctions []asm.Instructions

func addMatchCelExpr(
	exprs CelExprFunctions,
	arg *v1alpha1.ArgSelector,
	sig []v1alpha1.KProbeArg,
) (CelExprFunctions, error) {

	if len(arg.Values) != 1 {
		return nil, errors.New("addMatchCelExpr: only a single CelExpr value is supported")
	}

	nExprs := len(exprs)
	if nExprs >= MaxCelExprFunctions {
		return nil, fmt.Errorf("addMatchCelExpr: cannot allocate new cel expression function. No more than %d CelExpr allowed per policy", MaxCelExprFunctions)
	}

	idx := nExprs
	celExpr := arg.Values[0]

	args := make([]celbpf.ExprArg, 0, len(arg.Args))
	for i := range arg.Args {
		idx, ty, err := argIndexTypeFromArgs(arg, i, sig)
		if err != nil {
			return nil, err
		}
		args = append(args, celbpf.ExprArg{GenTy: int(ty), ArgOffset: int(idx)})
	}

	insts, err := celbpf.CompileFn(CelExprFuncName(idx), celExpr, args)
	if err != nil {
		return nil, err
	}

	exprs = append(exprs, insts)
	return exprs, nil

}

func parseMatchCelExpr(
	k *KernelSelectorState,
	arg *v1alpha1.ArgSelector,
	sig []v1alpha1.KProbeArg,
) error {
	exprs, err := addMatchCelExpr(k.celExprFunctions, arg, sig)

	if err != nil {
		return err
	}
	k.celExprFunctions = exprs
	idx := len(exprs) - 1
	// for the CelExpr selector, we use ->index to indicate the celExpr function to use
	WriteSelectorUint32(&k.data, uint32(idx))
	WriteSelectorUint32(&k.data, SelectorOpCelExpr)
	moff := AdvanceSelectorLength(&k.data)
	WriteSelectorUint32(&k.data, 0)
	WriteSelectorLength(&k.data, moff)
	return nil
}

func (cefs CelExprFunctions) RewriteProg(prog *ebpf.ProgramSpec) error {
	// add the generated functions as new instructions
	for _, insns := range cefs.functions() {
		prog.Instructions = append(prog.Instructions, insns...)
	}
	return nil
}

func (cefs CelExprFunctions) functions() map[string]asm.Instructions {
	fns := make(map[string]asm.Instructions)
	// first, fill in the functions for which we have an expression
	for i, insns := range cefs {
		fns[CelExprFuncName(i)] = insns
	}
	// next, fill in default functions (returning zero) for the rest of expressions
	// NB: this is needed, because otherwise loading will fail due to unresolved symbols.
	for i := len(fns); i < MaxCelExprFunctions; i++ {
		fnName := CelExprFuncName(i)
		fns[fnName] = celbpf.CompileEmptyFunction(fnName)
	}

	return fns
}
