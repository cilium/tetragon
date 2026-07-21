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

func rodataConfigContents() ([]byte, error) {
	return rodataConfigBytes(rodataCurrent())
}

func rodataConfigBytes(config rodataConfig) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, config); err != nil {
		return nil, fmt.Errorf("encoding rodata config: %w", err)
	}
	return buf.Bytes(), nil
}

// MapBuilderRodataConfig creates the shared, read-only rodata configuration map.
func MapBuilderRodataConfig(lds ...*Program) *Map {
	m := MapBuilderPin(rodataConfigMap, rodataConfigPin, lds...)

	// Configure sets Contents, which isn't checked by MapSpec.Compatible. It must
	// not otherwise change compatibility-relevant fields. BPF_F_MMAPABLE below
	// is safe because the collection loader independently adds it to data maps.
	m.Configure = func(spec *ebpf.MapSpec) error {
		if spec.Name != rodataConfigMap {
			return fmt.Errorf("unexpected rodata config map %q", spec.Name)
		}
		value, err := rodataConfigContents()
		if err != nil {
			return fmt.Errorf("getting read-only map contents: %w", err)
		}
		if features.HaveMapFlag(features.BPF_F_MMAPABLE) == nil {
			spec.Flags |= uint32(features.BPF_F_MMAPABLE)
		}
		spec.Contents = []ebpf.MapKV{{Key: uint32(0), Value: value}}
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

	return m
}
