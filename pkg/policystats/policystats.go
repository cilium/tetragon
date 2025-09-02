// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policystats

import (
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	PolicyStatsMapName = "policy_stats"
)

type PolicyAction uint8

const (
	// NB: values below should match the ones in bpf/lib/policy_stats.h
	InvalidAction               PolicyAction = 0
	PolicyPost                  PolicyAction = 1
	PolicySignal                PolicyAction = 2
	PolicyMonitorSignal         PolicyAction = 3
	PolicyOverride              PolicyAction = 4
	PolicyMonitorOverride       PolicyAction = 5
	PolicyNotifyEnforcer        PolicyAction = 6
	PolicyMonitorNotifyEnforcer PolicyAction = 7
	PolicyActionsNr                          = 8
)

type PolicyStats struct {
	ActionsCount [PolicyActionsNr]uint64
}

func StatsFromBPFMap(fname string) (*PolicyStats, error) {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer m.Close()

	var ret PolicyStats
	zero := uint32(0)
	if err = m.Lookup(&zero, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}

func GetPolicyStats(tp tracingpolicy.TracingPolicy) (*PolicyStats, error) {
	fname := filepath.Join(bpf.MapPrefixPath(), tracingpolicy.PolicyDir(tracingpolicy.Namespace(tp), tp.TpName()), PolicyStatsMapName)
	return StatsFromBPFMap(fname)
}
