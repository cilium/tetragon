// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

// Program sysfs hierarchy
//
// Each program is part of policy and sensor and defines PinName
// which determine its path in sysfs hierarchy, like:
//
//   /sys/fs/bpf/tetragon/policy/sensor/program/prog
//
// which broken down means:
//
//   /sys/fs/bpf/tetragon
//     - bpf (map) directory
//
//   policy/sensor
//     - defined by sensor.Policy/sensor.Name
//
//   program
//     - defined by program.PinName
//
//   prog
//     - fixed file name (prog_override for override program)
//
//  The program.PinPath field hods following portion of the path:
//     policy/sensor/program
//  and is initialized when the sensor is loaded.

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

func Builder(
	objFile, attach, label, pinName string,
	ty string,
) *Program {
	return &Program{
		Name:             objFile,
		Attach:           attach,
		Label:            label,
		PinPath:          "",
		PinName:          pinName,
		RetProbe:         false,
		ErrorFatal:       true,
		Override:         false,
		Type:             ty,
		LoadState:        Idle(),
		LoaderData:       struct{}{},
		MapLoad:          nil,
		unloader:         nil,
		PinMap:           make(map[string]*Map),
		Link:             nil,
		Prog:             nil,
		Policy:           "",
		RewriteConstants: make(map[string]any),
	}
}

func GetProgramInfo(l *Program) (program, label, prog string) {
	return l.Name, l.Label, l.PinPath
}

type MapLoad struct {
	Name string
	Load func(m *ebpf.Map, pinPathPrefix string) error
}

type MultiKprobeAttachData struct {
	Symbols   []string
	Cookies   []uint64
	Overrides []string
}

type UprobeAttachData struct {
	Path         string
	Symbol       string
	Address      uint64
	Offset       uint64
	RefCtrOffset uint64
}

type MultiUprobeAttachSymbolsCookies struct {
	Symbols       []string
	Addresses     []uint64
	Offsets       []uint64
	RefCtrOffsets []uint64
	Cookies       []uint64
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
	// PinName
	PinName string

	// RetProbe indicates whether a kprobe/uprobe is a kretprobe/uretprobe
	RetProbe bool
	// ErrorFatal indicates whether a program must load and fatal otherwise.
	// Most program will set this to true. For example, kernel functions hooks
	// may change across verions so different names are attempted, hence
	// avoiding fataling when the first attempt fails.
	ErrorFatal bool

	// Needs override bpf program
	Override        bool
	OverrideFmodRet bool

	// Needs write offload bpf program
	SleepableOffload bool

	// Type is the type of BPF program. For example, tc, skb, tracepoint,
	// etc.
	Type      string
	LoadState State

	// LoaderData represents per-type specific fields.
	LoaderData any

	// AttachData represents specific data for attaching probe
	AttachData any

	// Functions to call after loading maps to populate them
	MapLoad []*MapLoad

	// unloader for the program. nil if not loaded.
	unloader         unloader.Unloader
	unloaderOverride unloader.Unloader

	PinMap map[string]*Map

	// available when program.KeepCollection is true
	LC *LoadedCollection

	// Initialized map of constants to be populated in the program at
	// loading time.
	RewriteConstants map[string]any

	// Type information used for CO-RE relocations.
	KernelTypes *btf.Spec

	// Tail call prefix/map
	TcPrefix string
	TcMap    *Map

	Link link.Link
	Prog *ebpf.Program

	// policy name the program belongs to
	Policy string

	// Information of all maps used and loaded by this program by map ID. This
	// is populated after load and used for map memlock accounting.
	LoadedMapsInfo map[int]bpf.ExtendedMapInfo
}

func (p *Program) String() string {
	return fmt.Sprintf("Program{Name:%s Attach:%s Label:%s PinPath:%s}", p.Name, p.Attach, p.Label, p.PinPath)
}

func (p *Program) SetRetProbe(ret bool) *Program {
	p.RetProbe = ret
	return p
}

func (p *Program) SetLoaderData(d any) *Program {
	p.LoaderData = d
	return p
}

func (p *Program) SetAttachData(d any) *Program {
	p.AttachData = d
	return p
}

func (p *Program) SetTailCall(prefix string, m *Map) *Program {
	p.TcPrefix = prefix
	p.TcMap = m
	return p
}

func (p *Program) SetPolicy(policy string) *Program {
	p.Policy = policy
	return p
}

func (p *Program) Unload(unpin bool) error {
	if p.unloader == nil {
		return nil
	}
	if err := p.unloader.Unload(unpin); err != nil {
		return fmt.Errorf("failed to unload: %w", err)
	}
	if p.unloaderOverride != nil {
		if err := p.unloaderOverride.Unload(unpin); err != nil {
			return fmt.Errorf("failed to unload override: %w", err)
		}
	}
	p.unloader = nil
	p.unloaderOverride = nil
	// The above unloader can succeed while not removing a pin to the program
	// because of option.Config.KeepSensorsOnExit, and thus the maps remain.
	if !p.Prog.IsPinned() {
		p.LoadedMapsInfo = nil
	}
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
