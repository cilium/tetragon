// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package program

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTracingMultiOpen(t *testing.T) {
	for _, tt := range []struct {
		name       string
		retProbe   bool
		attachType ebpf.AttachType
	}{
		{name: "fentry", attachType: ebpf.AttachTraceFEntryMulti},
		{name: "fexit", retProbe: true, attachType: ebpf.AttachTraceFExitMulti},
	} {
		t.Run(tt.name, func(t *testing.T) {
			load := &Program{RetProbe: tt.retProbe}
			target := &ebpf.Program{}
			spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
				"main": {
					AttachType:   ebpf.AttachTraceFEntry,
					AttachTo:     "target",
					AttachTarget: target,
				},
				"tail": {
					AttachType:   ebpf.AttachTraceFEntry,
					AttachTo:     "target",
					AttachTarget: target,
				},
			}}

			require.NoError(t, TracingMultiOpen(load)(spec))
			for _, prog := range spec.Programs {
				assert.Equal(t, tt.attachType, prog.AttachType)
				assert.Empty(t, prog.AttachTo)
				assert.Nil(t, prog.AttachTarget)
			}
		})
	}
}
