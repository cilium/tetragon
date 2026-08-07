// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	rodataConfigMap = ".rodata.config"
	rodataConfigPin = "rodata_config"
)

type rodataConfig struct {
	IterNum        uint8
	UsePerfRingBuf uint8
	Pad            [6]uint8
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func rodataCurrent() rodataConfig {
	// We can't use numeric iterator until we get following fix from 6.9 kernel:
	//   4f81c16f50ba bpf: Recognize that two registers are safe when their ranges match
	// otherwise our loop code crosses 1mil instructions verifier limit.
	iterNum := b2u8(bpf.HasKfunc("bpf_iter_num_new") && kernels.MinKernelVersion("6.9"))

	// perf ring buffer is enabled by --use-perf-ring-buffer option
	usePerfRingBuf := b2u8(option.Config.UsePerfRingBuffer)

	return rodataConfig{
		IterNum:        iterNum,
		UsePerfRingBuf: usePerfRingBuf,
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
