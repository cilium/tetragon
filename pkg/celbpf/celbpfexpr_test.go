// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>

//go:build !windows

package celbpf

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

type myInt interface {
	~int32 | ~int64 | ~uint32 | ~uint64
}

func compare[T myInt](left, right T, op string) bool {
	switch op {
	case "<":
		return left < right
	case "<=":
		return left <= right
	case ">":
		return left > right
	case ">=":
		return left >= right
	case "==":
		return left == right
	case "!=":
		return left != right
	}
	return false
}

func boolToInt(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func addTestsTyped[T myInt](values []T, operators []string) []exprTest {
	var ret []exprTest

	literal := func(x any) string {
		switch x.(type) {
		case int32:
			return fmt.Sprintf("int32(%d)", x)
		case uint32:
			return fmt.Sprintf("uint32(%du)", x)
		case int64:
			return fmt.Sprintf("%d", x)
		case uint64:
			return fmt.Sprintf("%du", x)
		default:
			panic(fmt.Sprintf("cannot produce literal for value of type %T", x))
		}
	}

	for _, left := range values {
		for _, right := range values {
			for _, op := range operators {
				ret = append(ret, exprTest{
					expr: fmt.Sprintf("%s %s %s", literal(left), op, literal(right)),
					ret:  boolToInt(compare(left, right, op)),
				})
			}
		}
	}
	return ret
}

// testComparisons generates test cases for all comparison operators
func testComparisons() []exprTest {
	var ret []exprTest
	operators := []string{"<", "<=", ">", ">=", "==", "!="}

	ret = append(ret, addTestsTyped([]int32{5, 10, -5, -10}, operators)...)
	ret = append(ret, addTestsTyped([]int64{5, 10, -5, -10}, operators)...)
	ret = append(ret, addTestsTyped([]uint32{5, 10}, operators)...)
	ret = append(ret, addTestsTyped([]uint64{5, 10}, operators)...)

	return ret
}

type exprTest struct {
	expr string
	ret  uint32
}

func TestExprs(t *testing.T) {
	if !Supported() {
		t.Skip()
	}

	testCases := []exprTest{
		{"true", 1},
		{"false", 0},
		{"!(10 == 5)", 1},
		{"!(10 == 10)", 0},
		{"10 == 10 && 10 == 5", 0},
		{"10 == 10 || 10 == 5", 1},
		{"(10 == 10) == (10 == 10)", 1},
		{"(5 == 10) == (10 == 5)", 1},
		{"(5 == 10) == (10 == 10)", 0},
		{"5 - 10 == -5", 1},
		{"5u - 10u == 18446744073709551611u", 1},
		{"5 + 10 == 15", 1},
		{"18446744073709551611u + 6u == 1u", 1},
		{"int32(-1) == int32(4294967295)", 1},
		{"uint32(6u) == uint32(17179869190u)", 1},
		{"uint32(10u) == uint32(5u) + uint32(5u)", 1},
		{"uint32(3u) == uint32(5u) - uint32(2u)", 1},
		{"int32(10) == int32(5) + int32(5)", 1},
		{"int32(-2) == int32(5) - int32(7)", 1},
	}
	testCases = append(testCases, testComparisons()...)

	for _, tc := range testCases {
		insts, err := Compile(tc.expr, nil, "tc")
		require.NoError(t, err, "Compiling expression %q failed", tc.expr)
		insts[0] = insts[0].WithSource(s{tc.expr})
		// t.Logf("expr:%q\ninsts[%d]:\n%s", tc.expr, len(insts), insts)
		prog, err := ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{
			Type:         ebpf.RawTracepoint,
			Instructions: insts,
			License:      "Dual BSD/GPL",
		}, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction})
		require.NoError(t, err, "Loading program for expr %q failed", tc.expr)
		defer prog.Close()
		val, err := prog.Run(&ebpf.RunOptions{})
		require.NoError(t, err)
		if tc.ret != val {
			t.Logf("insns:\n%s\n", insts)
			dumpProg(t, prog)
		}
		require.Equal(t, tc.ret, val, "result of %q was %d and not %d", tc.expr, val, tc.ret)
	}
}
