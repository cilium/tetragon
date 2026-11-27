// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	rodataConfigMap = ".rodata.config"
	rodataConfigPin = "rodata_config"
)

type rodataConfig struct {
	IterNum           uint8
	UsePerfRingBuf    uint8
	EnvVarsEnabled    uint8
	ParentsMapEnabled uint8
	BpfDebugEnabled   uint8
	KsymsMissing      uint8
	Pad               [2]uint8
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func rodataCurrent() rodataConfig {
	// numeric iterators, see bpf.HasIterNum()
	iterNum := b2u8(bpf.HasIterNum())

	// perf ring buffer is enabled by --use-perf-ring-buffer option
	usePerfRingBuf := b2u8(option.Config.UsePerfRingBuffer)

	// environment variables are enabled by --enable-process-environment-variables option
	envVarsEnabled := b2u8(option.Config.EnableProcessEnvironmentVariables)

	// parents match enabled by --parents-map-enabled option
	parentsMapEnabled := b2u8(option.Config.ParentsMapEnabled)

	// bpf debug match enabled by --bpf-debug
	bpfDebugEnabled := option.Config.BPFDebugAreas.ToBPFConfig()

	// kernel kallsyms table may omit symbols when CONFIG_KALLSYMS_ALL=n
	ksymsMissing := b2u8(program.KsymsMissing())

	return rodataConfig{
		IterNum:           iterNum,
		UsePerfRingBuf:    usePerfRingBuf,
		EnvVarsEnabled:    envVarsEnabled,
		ParentsMapEnabled: parentsMapEnabled,
		BpfDebugEnabled:   bpfDebugEnabled,
		KsymsMissing:      ksymsMissing,
	}
}

// MapBuilderRodataConfigAtInit builds Tetragon's own shared, read-only
// rodata configuration map, wired to the given program load descriptors.
//
// It must only be called at init time (e.g. assigned to a package-level
// var, as RodataConfigMap is) - see program.MapBuilderRodataConfigAtInit.
func MapBuilderRodataConfigAtInit(lds ...*program.Program) *program.Map {
	return program.MapBuilderRodataConfigAtInit(rodataConfigMap, rodataConfigPin,
		func() (any, error) { return rodataCurrent(), nil }, lds...)
}

// RodataConfigMap is Tetragon's own shared, read-only rodata configuration map.
var RodataConfigMap = MapBuilderRodataConfigAtInit(Execve)
