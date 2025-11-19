// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyconf

import (
	"errors"
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
	EnforceMode     Mode = 0
	MonitorMode     Mode = 1
	MonitorOnlyMode Mode = 2 // monitor and cannot be updated to enforce

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
		return InvalidMode, fmt.Errorf("failed to open bpf map %s: %w", fname, err)
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

func SetModeInBPFMap(fname string, mode Mode) error {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load map %q: %w", fname, err)
	}
	defer m.Close()

	conf := PolicyConf{
		Mode: mode,
	}
	zero := uint32(0)
	if err = m.Update(&zero, &conf, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("failed to update map %q with val %v: %w", fname, conf, err)
	}
	return nil
}

func SetPolicyMode(tp tracingpolicy.TracingPolicy, m Mode) error {
	// While we will never be called by collection.go with monitor_only,
	// enforce this anyway.
	if m == MonitorOnlyMode {
		return errors.New("cannot set monitor only policy mode")
	}

	// Check that the policy is not currently in monitor_only mode,
	// otherwise reject the mode update.
	currMode, err := PolicyMode(tp)
	if err != nil {
		return err
	}
	if currMode == MonitorOnlyMode {
		return errors.New("cannot set policy mode on a policy that is monitor only")
	}

	fname := filepath.Join(bpf.MapPrefixPath(), tracingpolicy.PolicyDir(tracingpolicy.Namespace(tp), tp.TpName()), PolicyConfMapName)
	return SetModeInBPFMap(fname, m)
}
