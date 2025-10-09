// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build arm64 && linux

package tracing

import (
	"errors"

	"github.com/cilium/ebpf"
	processapi "github.com/cilium/tetragon/pkg/api/processapi"
)

func populateUprobeRegs(m *ebpf.Map, regs []processapi.RegAssignment) error {
	return errors.New("register override is not supported")
}
