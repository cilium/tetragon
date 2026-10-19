// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package unloader

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Unloader describes how to unload a sensor resource, e.g.
// programs or maps.
type Unloader interface {
	Unload(unpin bool) error
}

// IgnoreUnpinNotSupported drops ErrNotSupported from an Unpin call. Older
// kernels cannot pin some link types (perf events, raw tracepoints), so
// there is nothing to unpin and it is not an error.
func IgnoreUnpinNotSupported(err error) error {
	if errors.Is(err, ebpf.ErrNotSupported) {
		return nil
	}
	return err
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
	for _, u := range slices.Backward(cu) {
		// Allow nil unloader, we just skip it..
		if u == nil {
			continue
		}
		if err := u.Unload(unpin); err != nil {
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
	var ret error
	if unpin {
		if err := IgnoreUnpinNotSupported(pu.Prog.Unpin()); err != nil {
			ret = errors.Join(ret, fmt.Errorf("unpin program: %w", err))
		}
	}
	return errors.Join(ret, pu.Prog.Close())
}

// ProgUnloader unpins and closes a BPF program.
type LinkUnloader struct {
	Link link.Link
}

func (lu LinkUnloader) Unload(unpin bool) error {
	var ret error
	if unpin {
		if err := IgnoreUnpinNotSupported(lu.Link.Unpin()); err != nil {
			ret = errors.Join(ret, fmt.Errorf("unpin link: %w", err))
		}
	}
	return errors.Join(ret, lu.Link.Close())
}
