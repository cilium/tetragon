// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	EnforcerDataMapName = "enforcer_data"
)

type EnforcerMap struct {
	*ebpf.Map
}

func openEnforcerMap(polName, polNamespace string, opts *ebpf.LoadPinOptions) (EnforcerMap, error) {
	fname := filepath.Join(
		bpf.MapPrefixPath(),
		tracingpolicy.PolicyDir(polNamespace, polName),
		EnforcerDataMapName)
	m, err := ebpf.LoadPinnedMap(fname, opts)
	if err != nil {
		return EnforcerMap{nil}, fmt.Errorf("failed to open enforcer map %q: %w", fname, err)
	}

	return EnforcerMap{m}, nil
}

// open policy enforecer map for reading
func OpenEnforcerMap(polName, polNamespace string) (EnforcerMap, error) {
	return openEnforcerMap(polName, polNamespace, &ebpf.LoadPinOptions{ReadOnly: true})
}

type EnforcerMapKey struct {
	PidTgid uint64 // pidtgid
}

type EnforcerMapVal struct {
	Err    int16
	Sig    int16
	FuncID uint32
	Arg    uint32
}

func (m EnforcerMap) Dump() (map[EnforcerMapKey]EnforcerMapVal, error) {
	ret := make(map[EnforcerMapKey]EnforcerMapVal)

	var key EnforcerMapKey
	var val EnforcerMapVal

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ret[key] = val
	}

	return ret, iter.Err()
}

func DumpEnforcerMap(polName, polNamespace string) (map[EnforcerMapKey]EnforcerMapVal, error) {
	m, err := OpenEnforcerMap(polName, polNamespace)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	return m.Dump()
}

// NB: only meant for testing
func ResetEnforcerMap(_ *testing.T, polName, polNamespace string) error {
	m, err := openEnforcerMap(polName, polNamespace, &ebpf.LoadPinOptions{ReadOnly: false})
	if err != nil {
		return err
	}
	defer m.Close()

	for {
		var key EnforcerMapKey
		if err := m.NextKey(nil, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return err
		}
		if err := m.Delete(&key); err != nil {
			return err
		}
	}
}
