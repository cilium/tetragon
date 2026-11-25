// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bpf

import (
	"debug/elf"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
)

//go:noinline
func uprobeMultiTarget() {}

// fileOffset returns the offset in the executable of the function at the
// given address, using its executable PT_LOAD segment.
func fileOffset(t *testing.T, path string, addr uint64) uint64 {
	f, err := elf.Open(path)
	require.NoError(t, err)
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && prog.Flags&elf.PF_X != 0 &&
			prog.Vaddr <= addr && addr < prog.Vaddr+prog.Memsz {
			return addr - prog.Vaddr + prog.Off
		}
	}
	t.Skipf("function address %#x is not in an executable segment (PIE?)", addr)
	return 0
}

// HasUprobeMulti must match whether a uprobe_multi link can be attached to a
// real function of the test binary. The detection used to
// attach to address 1, which arm64 rejects because uprobes must be at
// instruction-aligned addresses there, so it reported no support on arm64
// kernels that have it.
func TestHasUprobeMulti(t *testing.T) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "test_upm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceUprobeMulti,
		License:    "MIT",
	})
	if err != nil {
		// The kernel (or an unprivileged user) can't load uprobe_multi
		// programs, so the agent can't use them either.
		t.Logf("loading a uprobe_multi program failed: %v", err)
		require.False(t, HasUprobeMulti())
		return
	}
	defer prog.Close()

	// go test strips the symbol table, so attach by file offset.
	const exe = "/proc/self/exe"
	off := fileOffset(t, exe, uint64(reflect.ValueOf(uprobeMultiTarget).Pointer()))
	ex, err := link.OpenExecutable(exe)
	require.NoError(t, err)

	// Before 6.6, the program loads, but creating the link fails with
	// EINVAL, which cilium/ebpf doesn't report as ErrNotSupported. So any
	// failure to attach means the agent can't use uprobe_multi links.
	um, err := ex.UprobeMulti(nil, prog, &link.UprobeMultiOptions{Addresses: []uint64{off}})
	if err != nil {
		t.Logf("attaching a uprobe_multi link failed: %v", err)
		require.False(t, HasUprobeMulti(), "uprobe_multi was detected, but attaching a link failed: %v", err)
		return
	}
	um.Close()
	require.True(t, HasUprobeMulti(), "a uprobe_multi link was attached, but it was not detected")
}
