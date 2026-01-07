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
		{name: cgOperators.Equals, opts: []cgDecls.FunctionOpt{
			cgDecls.Overload(cgOverloads.Equals, []*cgTypes.Type{paramA, paramA}, cgTypes.BoolType),
		}},
		{name: cgOperators.Add, opts: addOperatorFunctionOpts()},
		{name: cgOperators.Subtract, opts: subOperatorFunctionOpts()},
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

func checkerAddArguments(checkerEnv *cgChecker.Env, args []exprArg) error {
	// add argument identifiers
	for i := range args {
		arg := cgDecls.NewVariable("arg"+strconv.Itoa(i), args[i].ty)
		checkerEnv.AddIdents(arg)
	}
	return nil
}

func newCheckerEnv(args []exprArg) (*cgChecker.Env, error) {
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
