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
	}

	for _, tc := range testCase {
		insts, err := Compile(tc.expr)
		require.NoError(t, err)
		// t.Logf("expr:%q\ninsts[%d]:\n%s", tc.expr, len(insts), insts)
		prog, err := ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{
			Type:         ebpf.RawTracepoint,
			Instructions: insts,
			License:      "Dual BSD/GPL",
		}, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction})
		require.NoError(t, err)
		defer prog.Close()
		val, err := prog.Run(&ebpf.RunOptions{})
		require.NoError(t, err)
		require.Equal(t, tc.ret, val, "result of %q was %d and not %d", tc.expr, val, tc.ret)
	}
}
