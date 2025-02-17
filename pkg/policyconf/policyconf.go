// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyconf

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type Mode uint8

const (
	InvalidMode Mode = Mode(^uint8(0))
	// NB: values below should match the ones in bpf/lib/policy_conf.h
	EnforceMode Mode = 0
	MonitorMode Mode = 1

	PolicyConfMapName = "policy_conf"
)

// NB: if we add more fields here, we would need to modify SetModeInBPFMap to do a read-modify
// operation to set the mode.
type PolicyConf struct {
	Mode Mode
}

func ParseMode(s string) (Mode, error) {
	switch s {
	case "enforce":
		return EnforceMode, nil
	case "monitor":
		return MonitorMode, nil
	}

	return InvalidMode, fmt.Errorf("invalid mode: %q", s)
}

func ModeFromBPFMap(fname string) (Mode, error) {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return InvalidMode, err
	}
	defer m.Close()

	var ret PolicyConf
	zero := uint32(0)
	if err = m.Lookup(&zero, &ret); err != nil {
		return InvalidMode, err
	}
	return ret.Mode, nil
}

func PolicyMode(tp tracingpolicy.TracingPolicy) (Mode, error) {
	fname := filepath.Join(bpf.MapPrefixPath(), tracingpolicy.PolicyDir(tracingpolicy.Namespace(tp), tp.TpName()), PolicyConfMapName)
	return ModeFromBPFMap(fname)
}
