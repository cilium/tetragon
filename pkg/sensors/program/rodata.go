// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
)

type rodataConfig struct {
	IterNum uint8
	Pad     [7]uint8
}

func currentRodataConfig() rodataConfig {
	// We can't use numeric iterator until we get following fix from 6.9 kernel:
	//   4f81c16f50ba bpf: Recognize that two registers are safe when their ranges match
	// otherwise our loop code crosses 1mil instructions verifier limit.
	iterNum := uint8(0)
	if bpf.HasKfunc("bpf_iter_num_new") && kernels.MinKernelVersion("6.9") {
		iterNum = 1
	}
	return rodataConfig{IterNum: iterNum}
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
	v, ok := spec.Variables["rodata_config"]
	if !ok {
		return nil
	}
	return setConstant(v, currentRodataConfig())
}
