// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package celbpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canary = uint64(0xdeadbeefdeadbeef)

// Compile expr in value mode, run it, and return the 64-bit result.
//
// BPF_PROG_RUN can only return a 32-bit value, so the result cannot come back
// through prog.Run. The program stores it into a one-element array map
// instead, and the test reads it from there.
func runValueExpr(t *testing.T, expr string) uint64 {
	t.Helper()

	out, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	require.NoError(t, err)
	defer out.Close()

	// write canary so we can tell if a result was never written
	require.NoError(t, out.Put(uint32(0), canary))

	fnName := "myfn"
	insns, _, err := CompileValueFn(fnName, expr, nil, nil)
	require.NoError(t, err, "compiling %q failed", expr)

	main := asm.Instructions{
		asm.Call.Label(fnName),

		// R0 holds the 64-bit result
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),

		// bpf_map_lookup_elem(out, 0)
		asm.LoadMapPtr(asm.R1, out.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -24),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ret"),

		// *out[0] = result
		asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),

		asm.Return().WithSymbol("ret"),
	}
	fnTy := btfTestArgExprFnTy("main")
	main[0] = btf.WithFuncMetadata(main[0].WithSymbol(fnTy.Name), fnTy).WithSource(s{expr})

	insns = append(main, insns...)
	prog, err := ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{
		Type:         ebpf.RawTracepoint,
		Instructions: insns,
		License:      "Dual BSD/GPL",
	}, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction})
	require.NoError(t, err, "loading program for %q failed", expr)
	defer prog.Close()

	_, err = prog.Run(&ebpf.RunOptions{})
	require.NoError(t, err)

	var got uint64
	require.NoError(t, out.Lookup(uint32(0), &got))
	if got == canary {
		t.Logf("insns:\n%s\n", insns)
		dumpProg(t, prog)
		t.Fatalf("program for %q never stored a result", expr)
	}
	return got
}

type valueExprTest struct {
	expr string
	ret  uint64
}

func TestValueExprs(t *testing.T) {
	if !Supported() {
		t.Skip()
	}

	testCases := []valueExprTest{
		{"41 + 1", 42},
		{"and(12, 10)", 8},
		{"or(12, 10)", 14},
		{"0 - 1", 0xffffffffffffffff},
		{"18446744073709551615u", 0xffffffffffffffff},

		// values that would trigger an issue on a 32-bit return
		{"2147483648", 0x80000000},
		{"4294967296 + 42", 0x10000002a},
		{"lsh(1, 40)", 1 << 40},
		{"9223372036854775807", 0x7fffffffffffffff},
		{"9223372036854775807 + 1", 0x8000000000000000},
	}

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			require.Equal(t, tc.ret, runValueExpr(t, tc.expr),
				"result of %q", tc.expr)
		})
	}
}

func TestCompileValueType(t *testing.T) {
	accepted := []string{
		"41 + 1",
		"18446744073709551615u",
		"0 - 1",
		"and(12, 10)",
	}
	for _, expr := range accepted {
		t.Run("ok/"+expr, func(t *testing.T) {
			_, _, err := CompileValue(expr, nil, nil, "tc")
			require.NoError(t, err)
		})
	}

	rejected := []string{
		"true",
		"10 == 10",
		"int32(1) + int32(2)",
		"uint32(1u)",
	}
	for _, expr := range rejected {
		t.Run("bad/"+expr, func(t *testing.T) {
			_, _, err := CompileValue(expr, nil, nil, "tc")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "int64 or uint64")
		})
	}
}
