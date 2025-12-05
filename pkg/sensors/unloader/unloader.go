// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package unloader

import (
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Unloader describes how to unload a sensor resource, e.g.
// programs or maps.
type Unloader interface {
	Unload(unpin bool) error
}

// chainUnloader is an unloader for multiple resources.
// Useful when a loading operation needs to be unwinded due to an error.
type ChainUnloader []Unloader

type chainUnloaderError struct {
	errors []error
}

func (cue chainUnloaderError) Error() string {
	strs := []string{}
	for _, e := range cue.errors {
		strs = append(strs, e.Error())
	}
	return strings.Join(strs, "; ")
}

func (cu ChainUnloader) Unload(unpin bool) error {
	var cue chainUnloaderError
	for i := len(cu) - 1; i >= 0; i-- {
		// Allow nil unloader, we just skip it..
		if (cu)[i] == nil {
			continue
		}
		if err := (cu)[i].Unload(unpin); err != nil {
			cue.errors = append(cue.errors, err)
		}
	}
	if len(cue.errors) > 0 {
		return cue
	}
	return nil
}

// ProgUnloader unpins and closes a BPF program.
type ProgUnloader struct {
	Prog *ebpf.Program
}

func (pu ProgUnloader) Unload(unpin bool) error {
	if unpin {
		pu.Prog.Unpin()
	}
	return pu.Prog.Close()
}

// ProgUnloader unpins and closes a BPF program.
type LinkUnloader struct {
	Link link.Link
}

func (lu LinkUnloader) Unload(unpin bool) error {
	if unpin {
		lu.Link.Unpin()
	}
	return lu.Link.Close()
}
