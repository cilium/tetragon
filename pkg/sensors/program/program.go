// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

func Builder(
	objFile, attach, label, pinFile string,
	ty string,
) *Program {
	return &Program{
		Name:               objFile,
		Attach:             attach,
		Label:              label,
		PinPath:            pinFile,
		RetProbe:           false,
		ErrorFatal:         true,
		Override:           false,
		Type:               ty,
		LoadState:          Idle(),
		LoaderData:         struct{}{},
		MapLoad:            nil,
		unloader:           nil,
		PinMap:             make(map[string]string),
		MaxEntriesMap:      make(map[string]uint32),
		MaxEntriesInnerMap: make(map[string]uint32),
	}
}

func GetProgramInfo(l *Program) (program, label, prog string) {
	return l.Name, l.Label, l.PinPath
}

type MapLoad struct {
	Index uint32
	Name  string
	Load  func(m *ebpf.Map, index uint32) error
}

type MultiKprobeAttachData struct {
	Symbols   []string
	Cookies   []uint64
	Overrides []string
}

type UprobeAttachData struct {
	Path   string
	Symbol string
}

type MultiUprobeAttachSymbolsCookies struct {
	Symbols []string
	Cookies []uint64
}

type MultiUprobeAttachData struct {
	// Path -> []{Symbol,Cookie}
	Attach map[string]*MultiUprobeAttachSymbolsCookies
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
	Override        bool
	OverrideFmodRet bool

	// Type is the type of BPF program. For example, tc, skb, tracepoint,
	// etc.
	Type      string
	LoadState State

	// LoaderData represents per-type specific fields.
	LoaderData interface{}

	// AttachData represents specific data for attaching probe
	AttachData interface{}

	MapLoad []*MapLoad

	// unloader for the program. nil if not loaded.
	unloader         unloader.Unloader
	unloaderOverride unloader.Unloader

	PinMap map[string]string

	// available when program.KeepCollection is true
	LC *LoadedCollection

	MaxEntriesMap      map[string]uint32
	MaxEntriesInnerMap map[string]uint32
}

func (p *Program) SetRetProbe(ret bool) *Program {
	p.RetProbe = ret
	return p
}

func (p *Program) SetLoaderData(d interface{}) *Program {
	p.LoaderData = d
	return p
}

func (p *Program) SetAttachData(d interface{}) *Program {
	p.AttachData = d
	return p
}

func (p *Program) Unload() error {
	if p.unloader == nil {
		return nil
	}
	if err := p.unloader.Unload(); err != nil {
		return fmt.Errorf("Failed to unload: %w", err)
	}
	if p.unloaderOverride != nil {
		if err := p.unloaderOverride.Unload(); err != nil {
			return fmt.Errorf("Failed to unload override: %w", err)
		}
	}
	p.unloader = nil
	p.unloaderOverride = nil
	return nil
}

func (p *Program) Unlink() error {
	ul, ok := p.unloader.(interface{ Unlink() error })
	if !ok {
		return fmt.Errorf("Unlink failed: unloader type %T of program %p does not support it", p.unloader, p)
	}
	return ul.Unlink()
}

func (p *Program) Relink() error {
	rl, ok := p.unloader.(interface{ Relink() error })
	if !ok {
		return fmt.Errorf("Relink failed: unloader type %T of program %p does not support it", p.unloader, p)
	}
	return rl.Relink()
}
