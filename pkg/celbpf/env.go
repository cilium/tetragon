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

	andFn = "and"
)

type fnOverload struct {
	name string
	args []*cgTypes.Type
	res  *cgTypes.Type
}

type fnOpts struct {
	name      string
	overloads []fnOverload
}

func getFnsOpts() []fnOpts {
	paramA := cgTypes.NewTypeParamType("A")
	return []fnOpts{
		// Equality
		{name: cgOperators.Equals, overloads: []fnOverload{
			{name: cgOverloads.Equals, args: []*cgTypes.Type{paramA, paramA}, res: cgTypes.BoolType},
		}},

		// !=
		{name: cgOperators.NotEquals, overloads: []fnOverload{
			{name: cgOverloads.NotEquals, args: []*cgTypes.Type{paramA, paramA}, res: cgTypes.BoolType},
		}},

		// Logical operations: And/Or/Not
		{name: cgOperators.LogicalAnd, overloads: []fnOverload{
			{name: cgOverloads.LogicalAnd, args: []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, res: cgTypes.BoolType},
		}},
		{name: cgOperators.LogicalOr, overloads: []fnOverload{
			{name: cgOverloads.LogicalOr, args: []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, res: cgTypes.BoolType},
		}},
		{name: cgOperators.LogicalNot, overloads: []fnOverload{
			{name: cgOverloads.LogicalNot, args: []*cgTypes.Type{cgTypes.BoolType}, res: cgTypes.BoolType},
		}},

		// Comparison operators
		//
		// NB(kkourt): Currently, we only support "ty <cmp> ty -> bool" comparisons. IOW,
		// for comparing an s32 to a int64, the user would have to cast one of them to the
		// same type as the other, and then do the comparison. This limitation might be
		// lifted in the future.

		// <
		{name: cgOperators.Less, overloads: intCmpOperatorFnOverloads("lt")},
		// <=
		{name: cgOperators.LessEquals, overloads: intCmpOperatorFnOverloads("lq")},
		// >
		{name: cgOperators.Greater, overloads: intCmpOperatorFnOverloads("gt")},
		// >=
		{name: cgOperators.GreaterEquals, overloads: intCmpOperatorFnOverloads("gq")},

		// Addition and Subtraction
		{name: cgOperators.Add, overloads: intBinaryOperatorFnOverloads("add")},
		{name: cgOperators.Subtract, overloads: intBinaryOperatorFnOverloads("sub")},

		// Bitwise functions
		// NB(kkourt): it seems that there is no way to add custom operators to CEL
		{name: andFn, overloads: intBinaryOperatorFnOverloads(andFn)},

		// Integer casting
		{name: int32Fn, overloads: []fnOverload{
			{name: "s32fromint", args: []*cgTypes.Type{cgTypes.IntType}, res: s32Ty},
		}},
		{name: uint32Fn, overloads: []fnOverload{
			{name: "u32fromuint", args: []*cgTypes.Type{cgTypes.UintType}, res: u32Ty},
		}},
	}
}

func checkerAddFunctions(env *cgChecker.Env) error {

	fnsOpts := getFnsOpts()
	fns := make([]*cgDecls.FunctionDecl, 0, len(fnsOpts))
	for _, fnOpts := range fnsOpts {
		opts := make([]cgDecls.FunctionOpt, 0, len(fnOpts.overloads))
		for _, ov := range fnOpts.overloads {
			opts = append(opts, cgDecls.Overload(ov.name, ov.args, ov.res))
		}
		fn, err := cgDecls.NewFunction(fnOpts.name, opts...)
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
