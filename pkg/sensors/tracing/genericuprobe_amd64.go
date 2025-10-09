// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"github.com/cilium/ebpf"

	processapi "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/logger"
)

func populateUprobeRegs(m *ebpf.Map, regs []processapi.RegAssignment) error {
	uprobeRegs := processapi.UprobeRegs{}

	n := copy(uprobeRegs.Ass[:], regs)
	if n != len(regs) {
		logger.GetLogger().Warn("register assignments count mismatch", "#regs", len(regs))
	}
	uprobeRegs.Cnt = uint32(n)
	return m.Update(uint32(0), uprobeRegs, ebpf.UpdateAny)
}
