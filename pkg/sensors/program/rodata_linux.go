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

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
)

const (
	rodataConfigMap = ".rodata.config"
	rodataConfigPin = "rodata_config"
)

type rodataConfig struct {
	IterNum        uint8
	EnvVarsEnabled uint8
	Pad            [6]uint8
}

func rodataCurrent() rodataConfig {
	// We can't use numeric iterator until we get following fix from 6.9 kernel:
	//   4f81c16f50ba bpf: Recognize that two registers are safe when their ranges match
	// otherwise our loop code crosses 1mil instructions verifier limit.
	iterNum := uint8(0)
	if bpf.HasKfunc("bpf_iter_num_new") && kernels.MinKernelVersion("6.9") {
		iterNum = 1
	}

	envVarsEnabled := uint8(0)
	if option.Config.EnableProcessEnvironmentVariables {
		envVarsEnabled = 1
	}

	return rodataConfig{
		IterNum:        iterNum,
		EnvVarsEnabled: envVarsEnabled,
	}
}

// rodataConfigMaps tracks maps built via MapBuilderRodataConfig, keyed by
// ELF name, so the loader can resolve them to a single, well-known pinned
// instance across every sensor that references them, treating a resolution
// failure as fatal instead of "not shared, skip". Programs are loaded
// serially, so this needs no locking.
var rodataConfigMaps = map[string]string{} // elfName -> pinName

// registerRodataConfigMap marks elfName as a map that must resolve to a
// single, well-known pinned instance across every sensor that references it,
// with load failure treated as fatal. Populated only by
// MapBuilderRodataConfig. Re-registering the same elfName/pinName pair is a
// no-op (tolerates the same map being built more than once, e.g. in tests);
// registering the same elfName with a different pinName panics, since that
// indicates two unrelated maps colliding on one ELF name.
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
// map with the given ELF and pin names, populated by encoding load()'s
// result as little-endian bytes. This lets a caller - including a
// downstream project that imports Tetragon as a library and compiles its
// own BPF programs - define its own independent config map with its own
// value struct, reusing the same frozen-map machinery and cross-sensor
// sharing behavior as Tetragon's built-in rodata_config map.
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

// MapBuilderTetragonRodataConfig creates Tetragon's own shared, read-only
// rodata configuration map.
func MapBuilderTetragonRodataConfig(lds ...*Program) *Map {
	return MapBuilderRodataConfig(rodataConfigMap, rodataConfigPin,
		func() (rodataConfig, error) { return rodataCurrent(), nil }, lds...)
}
