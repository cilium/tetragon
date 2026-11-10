// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

// These types match bpf/lib/fmodret.h.
type fmodretKey struct {
	PIDTgid uint64
	Target  uint64
}

type fmodretAction struct {
	Scope      uint32
	Error      int32
	Generation uint64
}

type fmodretBinding struct {
	Target     uint64
	Generation uint64
}

type sharedFmodretProgram struct {
	load   *program.Program
	dir    string
	target uint64
	refs   int
}

type sharedFmodretPrograms struct {
	sync.Mutex
	next       uint64
	byFunction map[string]*sharedFmodretProgram
}

// A tracing program has a fixed BTF target and cannot be attached twice to
// the same trampoline. Share both the program and its link across policies.
// An fexit program clears handoffs skipped by another fmod_ret handler.
// The first policy loads the pair, and the last policy removes it.
func (shared *sharedMultiKprobe) acquireFmodret(bpfDir, symbol string, verbose int) (*sharedFmodretProgram, fmodretBinding, error) {
	cache := &shared.fmodret
	cache.Lock()
	defer cache.Unlock()
	if cache.next == math.MaxUint64 {
		return nil, fmodretBinding{}, errors.New("fmod_ret generation exhausted")
	}
	cache.next++
	generation := cache.next
	if target := cache.byFunction[symbol]; target != nil {
		target.refs++
		return target, fmodretBinding{target.target, generation}, nil
	}
	for _, name := range []string{"fmodret_tasks", "fmodret_targets"} {
		if m := shared.maps[name]; m == nil || m.MapHandle == nil {
			return nil, fmodretBinding{}, fmt.Errorf("shared fmod_ret map %s is not loaded", name)
		}
	}

	file, err := config.FindProgramFile(path.Join(option.Config.HubbleLib, "bpf_shared_fmodret.o"))
	if err != nil {
		return nil, fmodretBinding{}, err
	}
	load := program.Builder(file, symbol, "fmod_ret/security_task_prctl",
		multiKprobePinName("fmodret", symbol, generation), "generic_kprobe").SetPolicy(shared.load.Policy)
	load.PinPath = path.Join(shared.load.PinPath, load.PinName)
	load.RewriteConstants["fmodret_target"] = generation
	for _, name := range []string{"fmodret_tasks", "fmodret_targets"} {
		load.PinMap[name] = shared.maps[name]
	}
	dir := path.Join(bpfDir, load.PinPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmodretBinding{}, err
	}
	err = program.LoadProgramOpts(bpfDir, load, &program.LoadOpts{
		Open: func(spec *ebpf.CollectionSpec) error {
			for _, name := range []string{"shared_fmodret_override", "shared_fmodret_cleanup"} {
				prog := spec.Programs[name]
				if prog == nil {
					return fmt.Errorf("%s program not found", name)
				}
				prog.AttachTo = symbol
			}
			return nil
		},
		Attach: func(coll *ebpf.Collection, _ *ebpf.CollectionSpec, prog *ebpf.Program, _ *ebpf.ProgramSpec) (_ unloader.Unloader, err error) {
			// Install cleanup first and detach it last. Every handoff must
			// have invocation-end cleanup throughout the pair's lifetime.
			cleanup, err := attachFmodretCleanup(bpfDir, load, coll.Programs["shared_fmodret_cleanup"])
			if err != nil {
				prog.Close()
				return nil, err
			}
			defer func() {
				if err != nil {
					err = errors.Join(err, cleanup.Unload(true))
					prog.Close()
				}
			}()
			lnk, err := link.AttachTracing(link.TracingOptions{Program: prog})
			if err != nil {
				return nil, err
			}
			if err := program.LinkPin(lnk, bpfDir, load); err != nil {
				lnk.Close()
				return nil, err
			}
			load.Link = lnk
			return unloader.ChainUnloader{cleanup, unloader.ProgUnloader{Prog: prog}, unloader.LinkUnloader{Link: lnk}}, nil
		},
	}, verbose)
	if err != nil {
		if load.Prog != nil {
			err = errors.Join(err, load.Unload(true))
		}
		return nil, fmodretBinding{}, errors.Join(err, os.Remove(dir))
	}
	target := &sharedFmodretProgram{load: load, dir: dir, target: generation, refs: 1}
	if cache.byFunction == nil {
		cache.byFunction = make(map[string]*sharedFmodretProgram)
	}
	cache.byFunction[symbol] = target
	return target, fmodretBinding{target.target, generation}, nil
}

func attachFmodretCleanup(bpfDir string, load *program.Program, source *ebpf.Program) (_ unloader.Unloader, err error) {
	prog, err := source.Clone()
	if err != nil {
		return nil, err
	}
	u := unloader.ChainUnloader{unloader.ProgUnloader{Prog: prog}}
	defer func() {
		if err != nil {
			err = errors.Join(err, u.Unload(true))
		}
	}()
	if err := prog.Pin(path.Join(bpfDir, load.PinPath, "prog_cleanup")); err != nil {
		return nil, err
	}
	lnk, err := link.AttachTracing(link.TracingOptions{Program: prog})
	if err != nil {
		return nil, err
	}
	u = append(u, unloader.LinkUnloader{Link: lnk})
	if err := program.LinkPin(lnk, bpfDir, load, "cleanup"); err != nil {
		return nil, err
	}
	return u, nil
}

func (shared *sharedMultiKprobe) releaseFmodret(target *sharedFmodretProgram) error {
	cache := &shared.fmodret
	cache.Lock()
	defer cache.Unlock()
	target.refs--
	if target.refs != 0 {
		return nil
	}
	delete(cache.byFunction, target.load.Attach)
	err := target.load.Unload(true)
	// No policy can publish another action for this target after the last
	// reference is released. Remove any actions left by earlier invocations.
	tasks := shared.maps["fmodret_tasks"].MapHandle
	var key fmodretKey
	var action fmodretAction
	var stale []fmodretKey
	iter := tasks.Iterate()
	for iter.Next(&key, &action) {
		if key.Target == target.target {
			stale = append(stale, key)
		}
	}
	err = errors.Join(err, iter.Err())
	for _, key := range stale {
		if deleteErr := tasks.Delete(key); !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
			err = errors.Join(err, deleteErr)
		}
	}
	return errors.Join(err, os.Remove(target.dir))
}
