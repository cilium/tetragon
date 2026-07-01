// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
)

const (
	sharedRodataConfigMap = ".rodata.config"
	sharedRodataConfigVar = "rodata_config"
)

type rodataConfig struct {
	IterNum           uint8
	ParentsMapEnabled uint8
	EnvVarsEnabled    uint8
	Pad               [5]uint8
}

func currentRodataConfig() rodataConfig {
	// We can't use numeric iterator until we get following fix from 6.9 kernel:
	//   4f81c16f50ba bpf: Recognize that two registers are safe when their ranges match
	// otherwise our loop code crosses 1mil instructions verifier limit.
	iterNum := uint8(0)
	if bpf.HasKfunc("bpf_iter_num_new") && kernels.MinKernelVersion("6.9") {
		iterNum = 1
	}

	parentsMapEnabled := uint8(0)
	if option.Config.ParentsMapEnabled {
		parentsMapEnabled = 1
	}

	envVarsEnabled := uint8(0)
	if option.Config.EnableProcessEnvironmentVariables {
		envVarsEnabled = 1
	}

	return rodataConfig{
		IterNum:           iterNum,
		ParentsMapEnabled: parentsMapEnabled,
		EnvVarsEnabled:    envVarsEnabled,
	}
}

func setConstant(v *ebpf.VariableSpec, value any) error {
	if !v.Constant() {
		return fmt.Errorf("variable %s is not a constant", v.Name)
	}
	if err := v.Set(value); err != nil {
		return fmt.Errorf("failed to set config variable '%s': %w", v, err)
	}
	return nil
}

func initConfig(spec *ebpf.CollectionSpec) error {
	v, ok := spec.Variables[sharedRodataConfigVar]
	if !ok {
		return nil
	}
	return setConstant(v, currentRodataConfig())
}

func rodataConfigBytes(cfg rodataConfig) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, cfg); err != nil {
		return nil, fmt.Errorf("encoding shared rodata config: %w", err)
	}
	return buf.Bytes(), nil
}

func prepareSharedRodataConfigPin(pinPath string, flags uint32, contents []byte) error {
	if _, err := os.Stat(pinPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat shared rodata config map %s: %w", pinPath, err)
	}

	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return fmt.Errorf("loading shared rodata config map %s: %w", pinPath, err)
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("retrieving shared rodata config map info %s: %w", pinPath, err)
	}

	removePin := !info.Frozen() || info.Flags != flags
	if !removePin {
		got, err := m.LookupBytes(uint32(0))
		if err != nil {
			return fmt.Errorf("reading shared rodata config map %s: %w", pinPath, err)
		}
		removePin = len(got) != len(contents) || !bytes.Equal(got, contents)
	}

	if removePin {
		if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing stale shared rodata config map %s: %w", pinPath, err)
		}
	}
	return nil
}

// sharedRodataConfig is the shared, frozen .rodata.config map used by all
// large BPF programs that share the same config, along with the bpffs path
// it's pinned at.
type sharedRodataConfig struct {
	pinPath string
	m       *ebpf.Map
}

// loadOrCreateSharedRodataConfig returns the shared rodata config map pinned
// at pinPath. If no valid pin exists (none was there, or prepareSharedRodataConfigPin
// just evicted a stale one), it creates, populates, freezes and pins a fresh map from
// mapSpec/contents so it can be reused by every subsequent load, including this one.
func loadOrCreateSharedRodataConfig(pinPath string, mapSpec *ebpf.MapSpec, flags uint32, contents []byte) (*ebpf.Map, error) {
	if _, err := os.Stat(pinPath); err == nil {
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			return nil, fmt.Errorf("loading shared rodata config map %s: %w", pinPath, err)
		}
		return m, nil
	}

	spec := mapSpec.Copy()
	spec.Flags = flags
	spec.Contents = []ebpf.MapKV{{Key: uint32(0), Value: contents}}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("creating shared rodata config map: %w", err)
	}

	if err := m.Pin(pinPath); err != nil {
		m.Close()
		return nil, fmt.Errorf("pinning rodata config map to %s: %w", pinPath, err)
	}
	return m, nil
}

func setupSharedRodataConfig(bpfDir string, spec *ebpf.CollectionSpec) (*sharedRodataConfig, error) {
	mapSpec := spec.Maps[sharedRodataConfigMap]
	if mapSpec == nil {
		return nil, nil
	}
	if spec.Variables[sharedRodataConfigVar] == nil {
		return nil, fmt.Errorf("variable %s not found", sharedRodataConfigVar)
	}

	contents, err := rodataConfigBytes(currentRodataConfig())
	if err != nil {
		return nil, err
	}

	// The ebpf library adds BPF_F_MMAPABLE to data-section maps at collection
	// load time only when the running kernel supports it. Since we create this
	// map ourselves, mirror that feature check so the replacement map has the
	// same flags and remains usable on kernels older than 5.5.
	flags := mapSpec.Flags
	if features.HaveMapFlag(features.BPF_F_MMAPABLE) == nil {
		flags |= uint32(features.BPF_F_MMAPABLE)
	}

	pinPath := filepath.Join(bpfDir, "rodata")
	if err := prepareSharedRodataConfigPin(pinPath, flags, contents); err != nil {
		return nil, err
	}

	m, err := loadOrCreateSharedRodataConfig(pinPath, mapSpec, flags, contents)
	if err != nil {
		return nil, err
	}

	AddGlobalMap(sharedRodataConfigMap)
	return &sharedRodataConfig{pinPath: pinPath, m: m}, nil
}

// rodataConfigPin tracks the shared rodata config map pin.
// No locking needed: sensor load/unload is serialized by the sensor manager.
var rodataConfigPin = struct {
	path string
	refs int
}{}

func acquireRodataConfigPin(pinPath string) {
	rodataConfigPin.path = pinPath
	rodataConfigPin.refs++
}

func releaseRodataConfigPin(unpin bool) {
	if !unpin {
		return
	}

	rodataConfigPin.refs--
	if rodataConfigPin.refs > 0 {
		return
	}

	pinPath := rodataConfigPin.path
	rodataConfigPin.path = ""

	if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
		logger.GetLogger().Warn("Failed to unpin rodata config map", "map", pinPath, logfields.Error, err)
	}
}
