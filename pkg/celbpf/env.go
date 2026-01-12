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

		// Inequalities.
		//
		// NB(kkourt): some overloads are commented out, because they are not supported in code
		// generation. Should be easy to add as needed.

		// <
		{name: cgOperators.Less, opts: []cgDecls.FunctionOpt{
			// cgDecls.Overload(cgOverloads.LessBool, []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.LessInt64, []*cgTypes.Type{cgTypes.IntType, cgTypes.IntType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.LessInt64Uint64, []*cgTypes.Type{cgTypes.IntType, cgTypes.UintType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.LessUint64, []*cgTypes.Type{cgTypes.UintType, cgTypes.UintType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.LessUint64Int64, []*cgTypes.Type{cgTypes.UintType, cgTypes.IntType}, cgTypes.BoolType),
			cgDecls.Overload(ltS32, []*cgTypes.Type{s32Ty, s32Ty}, cgTypes.BoolType),
			cgDecls.Overload(ltU32, []*cgTypes.Type{u32Ty, u32Ty}, cgTypes.BoolType),
		}},
		// <=
		{name: cgOperators.LessEquals, opts: []cgDecls.FunctionOpt{
			// cgDecls.Overload(cgOverloads.LessEqualsBool, []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.LessEqualsInt64, []*cgTypes.Type{cgTypes.IntType, cgTypes.IntType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.LessEqualsInt64Uint64, []*cgTypes.Type{cgTypes.IntType, cgTypes.UintType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.LessEqualsUint64, []*cgTypes.Type{cgTypes.UintType, cgTypes.UintType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.LessEqualsUint64Int64, []*cgTypes.Type{cgTypes.UintType, cgTypes.IntType}, cgTypes.BoolType),
			cgDecls.Overload(lqS32, []*cgTypes.Type{s32Ty, s32Ty}, cgTypes.BoolType),
			cgDecls.Overload(lqU32, []*cgTypes.Type{u32Ty, u32Ty}, cgTypes.BoolType),
		}},
		// >
		{name: cgOperators.Greater, opts: []cgDecls.FunctionOpt{
			// cgDecls.Overload(cgOverloads.GreaterBool, []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.GreaterInt64, []*cgTypes.Type{cgTypes.IntType, cgTypes.IntType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.GreaterInt64Uint64, []*cgTypes.Type{cgTypes.IntType, cgTypes.UintType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.GreaterUint64, []*cgTypes.Type{cgTypes.UintType, cgTypes.UintType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.GreaterUint64Int64, []*cgTypes.Type{cgTypes.UintType, cgTypes.IntType}, cgTypes.BoolType),
			cgDecls.Overload(gtS32, []*cgTypes.Type{s32Ty, s32Ty}, cgTypes.BoolType),
			cgDecls.Overload(gtU32, []*cgTypes.Type{u32Ty, u32Ty}, cgTypes.BoolType),
		}},
		// >=
		{name: cgOperators.GreaterEquals, opts: []cgDecls.FunctionOpt{
			// cgDecls.Overload(cgOverloads.GreaterEqualsBool, []*cgTypes.Type{cgTypes.BoolType, cgTypes.BoolType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.GreaterEqualsInt64, []*cgTypes.Type{cgTypes.IntType, cgTypes.IntType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.GreaterEqualsInt64Uint64, []*cgTypes.Type{cgTypes.IntType, cgTypes.UintType}, cgTypes.BoolType),
			cgDecls.Overload(cgOverloads.GreaterEqualsUint64, []*cgTypes.Type{cgTypes.UintType, cgTypes.UintType}, cgTypes.BoolType),
			//cgDecls.Overload(cgOverloads.GreaterEqualsUint64Int64, []*cgTypes.Type{cgTypes.UintType, cgTypes.IntType}, cgTypes.BoolType),
			cgDecls.Overload(gqS32, []*cgTypes.Type{s32Ty, s32Ty}, cgTypes.BoolType),
			cgDecls.Overload(gqU32, []*cgTypes.Type{u32Ty, u32Ty}, cgTypes.BoolType),
		}},

		// Addition and Subtraction
		{name: cgOperators.Add, opts: addOperatorFunctionOpts()},
		{name: cgOperators.Subtract, opts: subOperatorFunctionOpts()},

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
