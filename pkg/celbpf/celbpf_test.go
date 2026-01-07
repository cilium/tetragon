// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>

//go:build !windows

package celbpf

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	gt "github.com/cilium/tetragon/pkg/generictypes"
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
		require.Equal(t, tc.ret, val, "result of %q was %d and not %d", tc.expr, val, tc.ret)
	}
}

// emulate msg_generic_kprobe for testing
type DummyMsg struct {
	argsoff [5]int64
	args    [24000]uint8
}

func prepareArgs(t *testing.T, hookArgs []any, exprArgs []int) (DummyMsg, []ExprArg) {
	var eargs []ExprArg
	var msg DummyMsg
	argsOff := 0
	for i := range 5 {
		if i < len(hookArgs) {
			val := hookArgs[i]
			n, err := binary.Encode(msg.args[argsOff:], binary.LittleEndian, val)
			if err != nil {
				t.Fatal(err)
			}
			msg.argsoff[i] = int64(argsOff)
			argsOff += n
		} else {
			msg.argsoff[i] = math.MaxInt64
		}
	}

	for _, eArg := range exprArgs {
		hArg := hookArgs[eArg]
		switch hArg.(type) {
		case int32:
			eargs = append(eargs, ExprArg{
				GenTy:     gt.GenericS32Type,
				ArgOffset: eArg,
			})
		case uint64:
			eargs = append(eargs, ExprArg{
				GenTy:     gt.GenericU64Type,
				ArgOffset: eArg,
			})
		case uint32:
			eargs = append(eargs, ExprArg{
				GenTy:     gt.GenericU32Type,
				ArgOffset: eArg,
			})
		case int64:
			eargs = append(eargs, ExprArg{
				GenTy:     gt.GenericS64Type,
				ArgOffset: eArg,
			})
		default:
			t.Fatalf("unknown type %T", hArg)
		}
	}

	return msg, eargs
}

func btfTestArgExprFnTy(fnName string) *btf.Func {
	return &btf.Func{
		Name: fnName,
		Type: &btf.FuncProto{
			Return: &btf.Int{
				Name:     "s32",
				Size:     4,
				Encoding: btf.Signed,
			},
			Params: []btf.FuncParam{
				{Name: "ctx", Type: &btf.Pointer{
					Target: &btf.Int{
						Name:     "u64",
						Size:     8,
						Encoding: btf.Unsigned,
					},
				}},
			},
		},
		Linkage: btf.StaticFunc,
	}
}

func TestArgExprs(t *testing.T) {
	testCase := []struct {
		expr     string
		ret      uint32
		hookArgs []any
		exprArgs []int
	}{
		{
			expr:     "arg0 == 42u",
			ret:      1,
			hookArgs: []any{uint64(42)},
			exprArgs: []int{0},
		},
		{
			expr:     "arg0 == 43u",
			ret:      0,
			hookArgs: []any{uint64(42)},
			exprArgs: []int{0},
		},
		{
			expr:     "arg0 == 0xaaaaaaaaaaaaaaaau",
			ret:      1,
			hookArgs: []any{uint64(0xaaaaaaaaaaaaaaaa)},
			exprArgs: []int{0},
		},
		{
			expr:     "arg0 == 0xaaaaaaaaaaaaaaaau",
			ret:      0,
			hookArgs: []any{uint64(0xbaaaaaaaaaaaaaab)},
			exprArgs: []int{0},
		},
		{
			expr:     "arg0 == uint32(42u)",
			ret:      1,
			hookArgs: []any{uint32(42)},
			exprArgs: []int{0},
		},
		{
			expr:     "arg0 == uint32(43u)",
			ret:      0,
			hookArgs: []any{uint32(42)},
			exprArgs: []int{0},
		},
		{
			expr:     "arg0 == int32(42)",
			ret:      1,
			hookArgs: []any{int32(0), uint64(0), int32(42)},
			exprArgs: []int{2},
		},
		{
			expr:     "arg0 == int32(0)",
			ret:      0,
			hookArgs: []any{int32(0), uint64(0), int32(42)},
			exprArgs: []int{2},
		},
		{
			expr:     "arg0 == arg1",
			ret:      1,
			hookArgs: []any{int32(42), uint64(0), int32(42)},
			exprArgs: []int{2, 0},
		},
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(DummyMsg{})),
		MaxEntries: 1,
	})
	require.NoError(t, err)
	defer m.Close()

	for _, tc := range testCase {
		data, eargs := prepareArgs(t, tc.hookArgs, tc.exprArgs)

		mapKey := uint32(0)
		err := m.Update(&mapKey, &data, 0)
		require.NoError(t, err, "update map value")

		fnName := "myfn"
		insns, err := CompileFn(fnName, tc.expr, eargs)
		require.NoError(t, err)
		prelude := asm.Instructions{
			// R1 map
			asm.LoadMapPtr(asm.R1, m.FD()),
			// R2 key
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -4),
			asm.StoreImm(asm.R2, 0, 0, asm.Word),
			// Lookup map[0]
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "ret"),

			// set arguments for call
			// R1: ->argsoff
			// R2: ->args
			asm.Mov.Reg(asm.R1, asm.R0),
			asm.Mov.Reg(asm.R2, asm.R1),
			asm.Add.Imm(asm.R2, 5*8),
			asm.Call.Label(fnName),
			asm.Return().WithSymbol("ret"),
		}
		fnTy := btfTestArgExprFnTy("main")
		prelude[0] = btf.WithFuncMetadata(prelude[0].WithSymbol(fnTy.Name), fnTy).WithSource(s{"main"})
		insns = append(prelude, insns...)
		prog, err := ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{
			Type:         ebpf.RawTracepoint,
			Instructions: insns,
			License:      "Dual BSD/GPL",
		}, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction})
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Logf("verifier error: %+v", ve)
			t.FailNow()
		}
		require.NoError(t, err)
		defer prog.Close()
		val, err := prog.Run(&ebpf.RunOptions{})
		require.NoError(t, err)
		require.Equal(t, tc.ret, val, "result of %q was %d and not %d", tc.expr, val, tc.ret)
	}
}
