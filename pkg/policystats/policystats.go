// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policystats

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	PolicySelectorStatsMapName = "selector_stats"
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
	PolicySet                   PolicyAction = 8
	PolicyMonitorSet            PolicyAction = 9
	PolicyNoPost                PolicyAction = 10
	PolicyActionsNr                          = 11
)

type PolicyStats struct {
	ActionsCount [PolicyActionsNr]uint64
}

func StatsFromBPFMapRange(fname string) ([]*PolicyStats, error) {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open bpf map %s: %w", fname, err)
	}
	defer m.Close()

	count := m.MaxEntries()
	ret := make([]*PolicyStats, 0, count)
	for key := range count {
		var stats PolicyStats
		if err = m.Lookup(&key, &stats); err != nil {
			return nil, fmt.Errorf("lookup failed: %w", err)
		}
		ret = append(ret, &stats)
	}
	return ret, nil
}

func (s *PolicyStats) Empty() bool {
	for _, cnt := range s.ActionsCount {
		if cnt != 0 {
			return false
		}
	}
	return true
}

func GetPolicyStats(tp tracingpolicy.TracingPolicy) (*PolicyStats, error) {
	stats, err := GetPolicySelectorStats(tp)
	if err != nil {
		return nil, err
	}

	ret := &PolicyStats{}
	for _, s := range stats {
		for i := range PolicyActionsNr {
			ret.ActionsCount[i] += s.ActionsCount[i]
		}
	}

	return ret, nil
}

func GetPolicySelectorStats(tp tracingpolicy.TracingPolicy) ([]*PolicyStats, error) {
	fname := filepath.Join(bpf.MapPrefixPath(), tracingpolicy.PolicyDir(tp.TpNamespace(), tp.TpName()), PolicySelectorStatsMapName)
	return StatsFromBPFMapRange(fname)
}
