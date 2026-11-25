// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/kernels"
)

func TestFullVerifierError(t *testing.T) {
	// The fall-through path sets r0 and passes. The jump path exits with r0
	// unset and fails.
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"prog": {
			Type:    ebpf.SocketFilter,
			License: "GPL",
			Instructions: asm.Instructions{
				asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
				asm.JEq.Imm(asm.R2, 0, "fail"),
				asm.Mov.Imm(asm.R0, 4242),
				asm.Return(),
				asm.Return().WithSymbol("fail"),
			},
		},
	}}

	_, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if errors.Is(err, unix.EPERM) {
		t.Skip("loading BPF needs privileges")
	}
	ve, ok := errors.AsType[*ebpf.VerifierError](err)
	require.True(t, ok, "expected a verifier error, got %v", err)
	// Since 5.8 (6f8a57ccf851), a level 1 log drops the paths that passed.
	if kernels.MinKernelVersion("5.8") {
		require.NotContains(t, strings.Join(ve.Log, "\n"), "r0 = 4242",
			"the level 1 log should keep only the failing path")
	}

	full := fullVerifierError(spec, ebpf.CollectionOptions{})
	require.NotNil(t, full)
	require.Contains(t, strings.Join(full.Log, "\n"), "r0 = 4242",
		"the full log should show the path that passed")
}
