// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>

//go:build !windows

package celbpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func TestExprs(t *testing.T) {
	testCase := []struct {
		expr string
		ret  uint32
	}{
		{"true", 1},
		{"false", 0},
		{"10 == 10", 1},
		{"10 == 5", 0},
		{"(10 == 10) == (10 == 10)", 1},
		{"(5 == 10) == (10 == 5)", 1},
		{"(5 == 10) == (10 == 10)", 0},
		{"10u == 10u", 1},
		{"10u == 5u", 0},
		{"int32(-10) == int32(-10)", 1},
		{"int32(-10) == int32(10)", 0},
		{"int32(-1) == int32(4294967295)", 1},
		{"uint32(10u) == uint32(10u)", 1},
		{"int32(-1) == int32(4294967295)", 1},
		{"uint32(6u) == uint32(17179869190u)", 1},
		{"uint32(6u) == uint32(0u)", 0},
	}

	for _, tc := range testCase {
		insts, err := Compile(tc.expr, "tc")
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
		require.Equal(t, tc.ret, val, "result of %q was %d and not %d", tc.expr, val, tc.ret)
	}
}
