// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package utils

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

var supportFentry = sync.OnceValue(func() error { return probeTracing(ebpf.AttachTraceFEntry) })

func SupportFentry() bool {
	return supportFentry() == nil
}

func probeTracing(attachType ebpf.AttachType) error {
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: attachType,
		AttachTo:   "security_file_mprotect",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}

	var prog *ebpf.Program
	var lnk link.Link
	var err error
	prog, err = ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		if lnk, err = link.AttachTracing(link.TracingOptions{Program: prog}); err == nil {
			lnk.Close()
		}
		prog.Close()
	}
	return err
}
