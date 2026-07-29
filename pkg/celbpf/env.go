// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CEL -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"fmt"
	"strconv"

	cgChecker "github.com/google/cel-go/checker"
	cgContainers "github.com/google/cel-go/common/containers"
	cgDecls "github.com/google/cel-go/common/decls"
	cgOperators "github.com/google/cel-go/common/operators"
	cgOverloads "github.com/google/cel-go/common/overloads"
	cgTypes "github.com/google/cel-go/common/types"

	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

var (
	int32Fn  = "int32"
	uint32Fn = "uint32"
)

func checkerAddFunctions(env *cgChecker.Env) error {
	paramA := cgTypes.NewTypeParamType("A")

	fnsOpts := []struct {
		name string
		opts []cgDecls.FunctionOpt
	}{
		// Equality
		{name: cgOperators.Equals, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload(cgOverloads.Equals, []*cgTypes.Type{paramA, paramA}, cgTypes.BoolType),
		}},

		// !=
		{name: cgOperators.NotEquals, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload(cgOverloads.NotEquals, []*cgTypes.Type{paramA, paramA}, cgTypes.BoolType),
		}},

		// Logical operations: And/Or/Not
		{name: cgOperators.LogicalAnd, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload(cgOverloads.LogicalAnd, []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, cgTypes.BoolType),
		}},
		{name: cgOperators.LogicalOr, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload(cgOverloads.LogicalOr, []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, cgTypes.BoolType),
		}},
		{name: cgOperators.LogicalNot, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload(cgOverloads.LogicalNot, []*cgTypes.Type{cgTypes.BoolType}, cgTypes.BoolType),
		}},

		// Comparison operators
		//
		// NB(kkourt): Currently, we only support "ty <cmp> ty -> bool" comparisons. IOW,
		// for comparing an s32 to a int64, the user would have to cast one of them to the
		// same type as the other, and then do the comparison. This limitation might be
		// lifted in the future.

		// <
		{name: cgOperators.Less, opts: intCmpOperatorFnOpts("lt")},
		// <=
		{name: cgOperators.LessEquals, opts: intCmpOperatorFnOpts("lq")},
		// >
		{name: cgOperators.Greater, opts: intCmpOperatorFnOpts("gt")},
		// >=
		{name: cgOperators.GreaterEquals, opts: intCmpOperatorFnOpts("gq")},

		// Addition and Subtraction
		{name: cgOperators.Add, opts: intBinaryOperatorFnOpts("add")},
		{name: cgOperators.Subtract, opts: intBinaryOperatorFnOpts("sub")},

		// Integer casting
		{name: int32Fn, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload("s32fromint", []*cgTypes.Type{cgTypes.IntType}, s32Ty),
		}},
		{name: uint32Fn, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload("u32fromuint", []*cgTypes.Type{cgTypes.UintType}, u32Ty),
		}},
	}

	fns := make([]*cgDecls.FunctionDecl, 0, len(fnsOpts))
	for _, fnOpts := range fnsOpts {
		fn, err := cgDecls.NewFunction(fnOpts.name, fnOpts.opts...)
		if err != nil {
			return err
		}
		fns = append(fns, fn)
	}

	return env.AddFunctions(fns...)
}

func convertType(conf_arg v1alpha1.KProbeArg) *cgTypes.Type {
	t, err := typeFromGenTy(gt.GenericTypeFromString(conf_arg.Type))
	if err != nil {
		t = unsupportedTy
	}
	return t
}

func checkerAddArguments(checkerEnv *cgChecker.Env, args []v1alpha1.KProbeArg) error {
	// add argument identifiers
	for i, a := range args {
		arg := cgDecls.NewVariable("arg"+strconv.Itoa(i), convertType(a))
		checkerEnv.AddIdents(arg)
	}
	return nil
}

func newCheckerEnv(args []v1alpha1.KProbeArg) (*cgChecker.Env, error) {
	tyProvider, err := NewProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize type provider: %w", err)
	}
	checkerEnv, err := cgChecker.NewEnv(cgContainers.DefaultContainer, tyProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize environment: %w", err)
	}

	if err := checkerAddFunctions(checkerEnv); err != nil {
		return nil, err
	}

	if err := checkerAddArguments(checkerEnv, args); err != nil {
		return nil, err
	}

	return checkerEnv, nil

}
