// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package celbpf

// This file implements evalCEL for evaluating celbpf expressions in userspace.
// This is meant to be used for testing randomized celbpf expressions.

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	celTypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/require"
)

type celNumber[T int32 | uint32] struct {
	value    T
	typeInfo *celTypes.Type
}

func (value celNumber[T]) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if typeDesc == reflect.TypeFor[T]() {
		return value.value, nil
	}
	return nil, errors.New("unsupported fixed-width integer conversion")
}

func (value celNumber[T]) ConvertToType(typeValue ref.Type) ref.Val {
	switch typeValue {
	case value.typeInfo:
		return value
	case celTypes.TypeType:
		return value.typeInfo
	default:
		return celTypes.NewErr("type conversion error from '%s' to '%s'", value.typeInfo, typeValue)
	}
}

func (value celNumber[T]) Equal(other ref.Val) ref.Val {
	otherValue, ok := other.(celNumber[T])
	if !ok {
		return celTypes.False
	}
	return celTypes.Bool(value.value == otherValue.value)
}

func (value celNumber[T]) Type() ref.Type {
	return value.typeInfo
}

func (value celNumber[T]) Value() any {
	return value.value
}

type celS32 = celNumber[int32]
type celU32 = celNumber[uint32]

func newCelS32(value int32) celS32 {
	return celS32{value: value, typeInfo: s32Ty}
}

func newCelU32(value uint32) celU32 {
	return celU32{value: value, typeInfo: u32Ty}
}

type celTestTypeAdapter struct {
	celTypes.Adapter
}

func (adapter celTestTypeAdapter) NativeToValue(value any) ref.Val {
	switch value := value.(type) {
	case celS32:
		return value
	case celU32:
		return value
	default:
		return adapter.Adapter.NativeToValue(value)
	}
}

func celLogicalNot(value ref.Val) ref.Val {
	boolValue, ok := value.(celTypes.Bool)
	if !ok {
		return celTypes.MaybeNoSuchOverloadErr(value)
	}
	return celTypes.Bool(!bool(boolValue))
}

// celBinArithOp builds a binary arithmetic CEL function from per-type operators.
// To add a new operation, just provide the four operator functions.
func celBinArithOp(
	intOp func(celTypes.Int, celTypes.Int) celTypes.Int,
	uintOp func(celTypes.Uint, celTypes.Uint) celTypes.Uint,
	s32Op func(int32, int32) int32,
	u32Op func(uint32, uint32) uint32,
) func(left, right ref.Val) ref.Val {
	return func(left, right ref.Val) ref.Val {
		switch left := left.(type) {
		case celTypes.Int:
			if r, ok := right.(celTypes.Int); ok {
				return intOp(left, r)
			}
		case celTypes.Uint:
			if r, ok := right.(celTypes.Uint); ok {
				return uintOp(left, r)
			}
		case celS32:
			if r, ok := right.(celS32); ok {
				return newCelS32(s32Op(left.value, r.value))
			}
		case celU32:
			if r, ok := right.(celU32); ok {
				return newCelU32(u32Op(left.value, r.value))
			}
		}
		return celTypes.MaybeNoSuchOverloadErr(left)
	}
}

var celAdd = celBinArithOp(
	func(a, b celTypes.Int) celTypes.Int { return a + b },
	func(a, b celTypes.Uint) celTypes.Uint { return a + b },
	func(a, b int32) int32 { return a + b },
	func(a, b uint32) uint32 { return a + b },
)

var celSubtract = celBinArithOp(
	func(a, b celTypes.Int) celTypes.Int { return a - b },
	func(a, b celTypes.Uint) celTypes.Uint { return a - b },
	func(a, b int32) int32 { return a - b },
	func(a, b uint32) uint32 { return a - b },
)

var celBitwiseAND = celBinArithOp(
	func(a, b celTypes.Int) celTypes.Int { return a & b },
	func(a, b celTypes.Uint) celTypes.Uint { return a & b },
	func(a, b int32) int32 { return a & b },
	func(a, b uint32) uint32 { return a & b },
)

var celBitwiseOR = celBinArithOp(
	func(a, b celTypes.Int) celTypes.Int { return a | b },
	func(a, b celTypes.Uint) celTypes.Uint { return a | b },
	func(a, b int32) int32 { return a | b },
	func(a, b uint32) uint32 { return a | b },
)

var celBitwiseXOR = celBinArithOp(
	func(a, b celTypes.Int) celTypes.Int { return a ^ b },
	func(a, b celTypes.Uint) celTypes.Uint { return a ^ b },
	func(a, b int32) int32 { return a ^ b },
	func(a, b uint32) uint32 { return a ^ b },
)

// Go shifts panic on a negative shift count, ensure they're positive.
// Also, the shift count operand for ebpf shift instructions is limited to 5/6
// bits which is why there's a value of 31/63
var celBitwiseLSH = celBinArithOp(
	func(a, b celTypes.Int) celTypes.Int { return a << (uint64(b) & 63) },
	func(a, b celTypes.Uint) celTypes.Uint { return a << (uint64(b) & 63) },
	func(a, b int32) int32 { return a << (uint(b) & 31) },
	func(a, b uint32) uint32 { return a << (uint(b) & 31) },
)

var celBitwiseRSH = celBinArithOp(
	func(a, b celTypes.Int) celTypes.Int { return a >> (uint64(b) & 63) },
	func(a, b celTypes.Uint) celTypes.Uint { return a >> (uint64(b) & 63) },
	func(a, b int32) int32 { return a >> (uint(b) & 31) },
	func(a, b uint32) uint32 { return a >> (uint(b) & 31) },
)

func celBitwiseNOT(value ref.Val) ref.Val {
	switch v := value.(type) {
	case celTypes.Int:
		return ^v
	case celTypes.Uint:
		return ^v
	case celS32:
		return newCelS32(^v.value)
	case celU32:
		return newCelU32(^v.value)
	}
	return celTypes.MaybeNoSuchOverloadErr(value)
}

func compareIntegers[T int32 | uint32 | celTypes.Int | celTypes.Uint](op string, left, right T) ref.Val {
	switch op {
	case "lt":
		return celTypes.Bool(left < right)
	case "lq":
		return celTypes.Bool(left <= right)
	case "gt":
		return celTypes.Bool(left > right)
	case "gq":
		return celTypes.Bool(left >= right)
	default:
		return celTypes.NewErr("unsupported integer inequality: %s", op)
	}
}

func celInequality(op string, left, right ref.Val) ref.Val {
	switch left := left.(type) {
	case celTypes.Int:
		right, ok := right.(celTypes.Int)
		if !ok {
			return celTypes.MaybeNoSuchOverloadErr(right)
		}
		return compareIntegers(op, left, right)
	case celTypes.Uint:
		right, ok := right.(celTypes.Uint)
		if !ok {
			return celTypes.MaybeNoSuchOverloadErr(right)
		}
		return compareIntegers(op, left, right)
	case celS32:
		right, ok := right.(celS32)
		if !ok {
			return celTypes.MaybeNoSuchOverloadErr(right)
		}
		return compareIntegers(op, left.value, right.value)
	case celU32:
		right, ok := right.(celU32)
		if !ok {
			return celTypes.MaybeNoSuchOverloadErr(right)
		}
		return compareIntegers(op, left.value, right.value)
	default:
		return celTypes.MaybeNoSuchOverloadErr(left)
	}
}

func getOverloadOpts(t *testing.T, o *fnOverload) []cel.OverloadOpt {
	var ret []cel.OverloadOpt
	switch o.name {
	case "u32fromuint":
		return append(ret, cel.UnaryBinding(func(value ref.Val) ref.Val {
			return newCelU32(uint32(value.(celTypes.Uint)))
		}))
	case "s32fromint":
		return append(ret, cel.UnaryBinding(func(value ref.Val) ref.Val {
			return newCelS32(int32(value.(celTypes.Int)))
		}))
	case "equals", "not_equals", "logical_and", "logical_or":
		return ret

	}

	if strings.HasPrefix(o.name, "sub_") {
		return append(ret, cel.BinaryBinding(celSubtract))
	}

	if strings.HasPrefix(o.name, "add_") {
		return append(ret, cel.BinaryBinding(celAdd))
	}

	if strings.HasPrefix(o.name, andFn) {
		return append(ret, cel.BinaryBinding(celBitwiseAND))
	}

	if strings.HasPrefix(o.name, orFn) {
		return append(ret, cel.BinaryBinding(celBitwiseOR))
	}

	if strings.HasPrefix(o.name, xorFn) {
		return append(ret, cel.BinaryBinding(celBitwiseXOR))
	}

	if strings.HasPrefix(o.name, notFn) {
		return append(ret, cel.UnaryBinding(celBitwiseNOT))
	}

	if strings.HasPrefix(o.name, lshFn) {
		return append(ret, cel.BinaryBinding(celBitwiseLSH))
	}

	if strings.HasPrefix(o.name, rshFn) {
		return append(ret, cel.BinaryBinding(celBitwiseRSH))
	}

	for _, ineq := range []string{"lt", "lq", "gt", "gq"} {
		prefix := ineq + "_"
		if strings.HasPrefix(o.name, prefix) {
			return append(ret, cel.BinaryBinding(func(v1 ref.Val, v2 ref.Val) ref.Val {
				return celInequality(ineq, v1, v2)
			}))
		}
	}

	if o.name == "logical_not" {
		return append(ret, cel.UnaryBinding(celLogicalNot))
	}

	t.Fatalf("TODO: implement getOverloadOpts for %s", o.name)
	return ret
}

func evalCEL(t *testing.T, expr string, hookArgs []any) uint32 {
	t.Helper()

	opts := []cel.EnvOption{
		cel.Types(s32Ty, u32Ty),
		cel.CustomTypeAdapter(celTestTypeAdapter{Adapter: celTypes.DefaultTypeAdapter}),
	}

	for _, fnOpt := range getFnsOpts() {
		fnOpts := make([]cel.FunctionOpt, 0, len(fnOpt.overloads))
		for _, o := range fnOpt.overloads {
			overloadOpts := getOverloadOpts(t, &o)
			fnOpts = append(fnOpts, cel.Overload(o.name, o.args, o.res, overloadOpts...))
		}
		opts = append(opts, cel.Function(fnOpt.name, fnOpts...))
	}

	values := make(map[string]any, len(hookArgs))
	for i, hookArg := range hookArgs {
		argName := "arg" + strconv.Itoa(i)
		switch value := hookArg.(type) {
		case int32:
			opts = append(opts, cel.Variable(argName, s32Ty))
			values[argName] = newCelS32(value)
		case int64:
			opts = append(opts, cel.Variable(argName, s64Ty))
			values[argName] = value
		case uint32:
			opts = append(opts, cel.Variable(argName, u32Ty))
			values[argName] = newCelU32(value)
		case uint64:
			opts = append(opts, cel.Variable(argName, u64Ty))
			values[argName] = value
		default:
			t.Fatalf("unknown hook type %T", hookArg)
		}
	}

	env, err := cel.NewCustomEnv(opts...)
	require.NoError(t, err)
	ast, issues := env.Compile(expr)
	require.NoError(t, issues.Err())
	prog, err := env.Program(ast)
	require.NoError(t, err)
	result, _, err := prog.Eval(values)
	require.NoError(t, err, "Failed to evaluate CEL program")

	boolResult, ok := result.(celTypes.Bool)
	require.True(t, ok, "CEL expression %q returned %T, not bool", expr, result)
	if bool(boolResult) {
		return 1
	}
	return 0
}

func TestEvalCEL(t *testing.T) {
	for _, tc := range argTestCases {
		require.Equal(t, tc.ret, evalCEL(t, tc.expr, tc.hookArgs))
	}
}
