// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yalue/native_endian"
)

type testStruct struct {
	i16 int16
	u16 uint16
	i32 int32
	u32 uint32
	i64 int64
	u64 uint64
}

func intValue(i interface{}) int64 {
	switch v := i.(type) {
	case int16:
		return int64(v)
	case uint16:
		return int64(v)
	case int32:
		return int64(v)
	case uint32:
		return int64(v)
	case int64:
		return v
	case uint64:
		return int64(v)
	}
	panic("not int")
}

func TestStructToStaticData(t *testing.T) {
	st := testStruct{1, 2, 3, 4, 5, 6}
	sd := StructToGlobals(st)

	expectations := []struct {
		n string
		v interface{}
	}{
		{"i16", st.i16},
		{"u16", st.u16},
		{"i32", st.i32},
		{"u32", st.u32},
		{"i64", st.i64},
		{"u64", st.u64},
	}

	for _, e := range expectations {
		if intValue(sd[e.n]) != intValue(e.v) {
			t.Fatalf("expected %s to be %v, but got %v", e.n, e.v, sd[e.n])
		}
	}
}

func TestRewriteStaticData(t *testing.T) {
	insns := asm.Instructions{
		asm.LoadMapValue(asm.R0, 0, 0),
		asm.LoadMapValue(asm.R0, 0, 8),
	}
	insns[0].Reference = ".rodata"
	insns[1].Reference = ".rodata"

	values := make([]byte, 16)
	u32 := uint32(0x01020304)
	native_endian.NativeEndian().PutUint64(values, uint64(u32))
	u64 := uint64(0xdeadbeefaffab0b0)
	native_endian.NativeEndian().PutUint64(values[8:], u64)

	cs := &ebpf.CollectionSpec{
		ByteOrder: native_endian.NativeEndian(),
		Maps: map[string]*ebpf.MapSpec{
			".rodata": {
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  16,
				MaxEntries: 1,
				Contents: []ebpf.MapKV{{
					Key:   0,
					Value: values,
				}},
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"prog": {
				Type:         ebpf.SocketFilter,
				Instructions: insns,
				License:      "MIT",
			},
		},
	}

	err := replaceGlobals(cs)
	if err != nil {
		t.Fatal(err)
	}

	expectedInsns := asm.Instructions{
		asm.LoadImm(asm.R0, int64(u32), asm.DWord),
		asm.LoadImm(asm.R0, int64(u64), asm.DWord),
	}

	for i, ins := range insns {
		if ins != expectedInsns[i] {
			t.Fatalf("Failed to rewrite static data, at instruction %d, expected: %v, got: %v", i, expectedInsns[i], ins)
		}
	}
}

func TestBPFReadGlobals(t *testing.T) {
	rlimit.RemoveMemlock()
	spec, err := ebpf.LoadCollectionSpec("../../bpf/objs/bpf_globals.o")
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the contents of the .rodata section
	err = spec.RewriteConstants(map[string]interface{}{
		"g_u16": int64(65535),
		"g_i16": int64(-32767),
		"g_u32": int64(4294967295),
		"g_i32": int64(-2147483648),
		"g_u64": int64(-1),
		"g_i64": int64(-9223372036854775808),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Now replace the map loads with immediate constant loads.
	err = replaceGlobals(spec)
	if err != nil {
		t.Fatal(err)
	}

	progSpec, ok := spec.Programs["read_globals_test"]
	if !ok {
		t.Fatal("read_globals_test program not found")
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		t.Fatal(err)
	}

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Fatalf("test failed at line %d", ret)
	}
}
