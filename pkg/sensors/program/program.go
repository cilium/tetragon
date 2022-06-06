// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package program

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

func Builder(
	objFile, attach, label, pinFile string,
	ty string,
) *Program {
	return &Program{
		Name:       objFile,
		Attach:     attach,
		Label:      label,
		PinPath:    pinFile,
		RetProbe:   false,
		ErrorFatal: true,
		Override:   false,
		Type:       ty,
		LoadState:  Idle(),
		TraceFD:    -1,
		LoaderData: struct{}{},
		unloader:   nil,
	}
}

func GetProgramInfo(l *Program) (program, label, prog string) {
	return l.Name, l.Label, l.PinPath
}

// Program reprents a BPF program.
type Program struct {
	// Name is the name of the BPF object file.
	Name string
	// Attach is the attachment point, e.g. the kernel function.
	Attach string
	// Label is the program section name to load from program.
	Label string
	// PinPath is the pinned path to this program. Note this is a relative path
	// based on the BPF directory FGS is running under.
	PinPath string

	// RetProbe indicates whether a kprobe is a kretprobe.
	RetProbe bool
	// ErrorFatal indicates whether a program must load and fatal otherwise.
	// Most program will set this to true. For example, kernel functions hooks
	// may change across verions so different names are attempted, hence
	// avoiding fataling when the first attempt fails.
	ErrorFatal bool

	// Needs override bpf program
	Override bool

	// Type is the type of BPF program. For example, tc, skb, tracepoint,
	// etc.
	Type      string
	LoadState State

	// TraceFD is needed because tracepoints are added different than kprobes
	// for example. The FD is to keep a reference to the tracepoint program in
	// order to delete it. TODO: This can be moved into loaderData for
	// tracepoints.
	TraceFD int

	// LoaderData represents per-type specific fields.
	LoaderData interface{}

	// unloader for the program. nil if not loaded.
	unloader unloader.Unloader
}

func (p *Program) SetRetProbe(ret bool) *Program {
	p.RetProbe = ret
	return p
}

func (p *Program) SetLoaderData(d interface{}) *Program {
	p.LoaderData = d
	return p
}

func (p *Program) Unload() error {
	if p.unloader == nil {
		return nil
	}
	if err := p.unloader.Unload(); err != nil {
		return fmt.Errorf("Failed to unload: %s", err)
	}
	p.unloader = nil
	return nil
}
