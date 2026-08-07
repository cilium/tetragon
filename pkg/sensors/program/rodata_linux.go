// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package program

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

var rodataConfigMaps = map[string]string{} // elfName -> pinName

func registerRodataConfigMap(elfName, pinName string) {
	if existing, ok := rodataConfigMaps[elfName]; ok {
		if existing != pinName {
			panic(fmt.Sprintf("required shared map %q already registered with pin %q, got %q", elfName, existing, pinName))
		}
		return
	}
	rodataConfigMaps[elfName] = pinName
}

func lookupRodataConfigMap(elfName string) (string, bool) {
	pinName, ok := rodataConfigMaps[elfName]
	return pinName, ok
}

// MapBuilderRodataConfig creates a shared, read-only, frozen configuration
// map with the given ELF and pin names, populated by load func
//
// T must be a fixed-layout struct usable with encoding/binary.Write
// (fixed-width integer fields and fixed-size arrays thereof only - no
// strings, slices, maps, or pointers). The encoded byte length of T must
// exactly match the compiled size of the corresponding ".rodata.<name>"
// section in the target BPF object, including any C-side padding.
func MapBuilderRodataConfig[T any](elfName, pinName string, load func() (T, error), lds ...*Program) *Map {
	m := MapBuilderPin(elfName, pinName, lds...)

	// Configure sets Contents, which isn't checked by MapSpec.Compatible. It must
	// not otherwise change compatibility-relevant fields. BPF_F_MMAPABLE below
	// is safe because the collection loader independently adds it to data maps.
	m.Configure = func(spec *ebpf.MapSpec) error {
		if spec.Name != elfName {
			return fmt.Errorf("unexpected rodata config map %q", spec.Name)
		}
		cfg, err := load()
		if err != nil {
			return fmt.Errorf("loading read-only map contents: %w", err)
		}
		var buf bytes.Buffer
		if err := binary.Write(&buf, binary.LittleEndian, cfg); err != nil {
			return fmt.Errorf("encoding read-only map contents: %w", err)
		}
		if features.HaveMapFlag(features.BPF_F_MMAPABLE) == nil {
			spec.Flags |= uint32(features.BPF_F_MMAPABLE)
		}
		spec.Contents = []ebpf.MapKV{{Key: uint32(0), Value: buf.Bytes()}}
		return nil
	}

	// verify it's frozen and the contents match
	m.Validate = func(m *ebpf.Map, spec *ebpf.MapSpec) error {
		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("querying read-only map: %w", err)
		}
		if !info.Frozen() {
			return errors.New("read-only map is not frozen")
		}
		if len(spec.Contents) != 1 {
			return fmt.Errorf("read-only map has %d configured entries", len(spec.Contents))
		}
		expected, ok := spec.Contents[0].Value.([]byte)
		if !ok {
			return fmt.Errorf("read-only map has unexpected configured value type %T", spec.Contents[0].Value)
		}
		got, err := m.LookupBytes(uint32(0))
		if err != nil {
			return fmt.Errorf("reading read-only map: %w", err)
		}
		if !bytes.Equal(got, expected) {
			return errors.New("read-only map contents differ")
		}
		return nil
	}

	registerRodataConfigMap(elfName, pinName)
	return m
}
