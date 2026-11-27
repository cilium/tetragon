// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func filter2TestSpec(withRodata bool) *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"generic_kprobe_process_filter":   {Name: "generic_kprobe_process_filter"},
			"generic_kprobe_process_filter_2": {Name: "generic_kprobe_process_filter_2"},
			"generic_kprobe_setup_event":      {Name: "generic_kprobe_setup_event"},
		},
		Maps: map[string]*ebpf.MapSpec{
			"kprobe_calls": {
				Name: "kprobe_calls",
				Type: ebpf.ProgramArray,
				Contents: []ebpf.MapKV{
					{Key: uint32(0), Value: "generic_kprobe_setup_event"},
					{Key: uint32(5), Value: "generic_kprobe_process_filter"},
					{Key: uint32(9), Value: "generic_kprobe_process_filter_2"},
				},
			},
		},
	}
	if withRodata {
		spec.Maps[".rodata.config"] = &ebpf.MapSpec{Name: ".rodata.config", Type: ebpf.Array}
	}
	return spec
}

func TestDropSplitFilterProgs(t *testing.T) {
	registerRodataConfigMapAtInit(".rodata.config", "rodata_config")

	t.Run("single mode", func(t *testing.T) {
		spec := filter2TestSpec(true)
		dropSplitFilterProgsIf(spec, true)

		require.NotContains(t, spec.Programs, "generic_kprobe_process_filter_2")
		require.Contains(t, spec.Programs, "generic_kprobe_process_filter")
		require.Contains(t, spec.Programs, "generic_kprobe_setup_event")
		require.Equal(t, []ebpf.MapKV{
			{Key: uint32(0), Value: "generic_kprobe_setup_event"},
			{Key: uint32(5), Value: "generic_kprobe_process_filter"},
		}, spec.Maps["kprobe_calls"].Contents)
	})

	for _, tc := range []struct {
		name       string
		iterNum    bool
		withRodata bool
	}{
		{"no iter num", false, true},
		{"no rodata config map", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := filter2TestSpec(tc.withRodata)
			dropSplitFilterProgsIf(spec, tc.iterNum)
			require.Equal(t, filter2TestSpec(tc.withRodata), spec)
		})
	}
}
