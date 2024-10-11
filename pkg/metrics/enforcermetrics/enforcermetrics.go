// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package enforcermetrics

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	EnforcerMissedMapName = "enforcer_missed_notifications"
)

var gState = newState()

func NewCollector() metrics.CollectorWithInit {
	return gState.newCollector()
}

func RegisterInfo(policy string, funcID uint32, argToInfo func(arg uint32) string) {
	gState.registerInfo(policy, funcID, argToInfo)
}

func UnregisterPolicy(policy string) {
	gState.unregisterPolicy(policy)
}

type state struct {
	missedNotifications metrics.CustomMetric
	// mu protects policies
	mu sync.Mutex
	// policies with an enforcer
	// policy_name -> func_id -> (arg -> info)
	policies map[string]map[uint32]func(arg uint32) string
}

func newState() *state {

	st := &state{
		policies: map[string]map[uint32]func(arg uint32) string{},
	}
	st.missedNotifications = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "enforcer", "missed_notifications_total",
		"The number of missed notifications by the enforcer.",
		nil, []metrics.ConstrainedLabel{
			// NB: these corresponds to "enum enforcer_missed_reason" in bpf. Unknown values
			// are mapped to "unspecified"
			{Name: "reason", Values: enforcerMissedNotificationsReasons},
		}, []metrics.UnconstrainedLabel{
			{Name: "policy", ExampleValue: "enforcer_policy"},
			{Name: "info", ExampleValue: ""},
		},
	))
	return st
}

func (st *state) newCollector() metrics.CollectorWithInit {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			st.missedNotifications,
		},
		st.collect,
		collectForDocs,
	)
}

// NB: should match bpf's struct enforcer_missed_key
type enforcerMissedMapKey struct {
	FuncId uint32
	Arg    uint32
	Reason uint32
}

var enforcerMissedNotificationsReasons = []string{"unspecified", "no_action", "overwritten"}

func (mk *enforcerMissedMapKey) reason() string {
	// NB: see bpf's enforcer_missed_reason
	switch mk.Reason {
	case 1:
		return "overwritten"
	default:
		return "unspecified"
	}
}

func (st *state) registerInfo(policy string, funcID uint32, argToInfoFn func(uint32) string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	m, ok := st.policies[policy]
	if !ok {
		st.policies[policy] = map[uint32]func(uint32) string{
			funcID: argToInfoFn,
		}
		return
	}
	m[funcID] = argToInfoFn
}

func (st *state) collect(ch chan<- prometheus.Metric) {
	st.mu.Lock()
	defer st.mu.Unlock()

	for policy, polM := range st.policies {
		path := program.PolicyMapPath(bpf.MapPrefixPath(), policy, EnforcerMissedMapName)
		m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})
		if err != nil {
			continue
		}

		var key enforcerMissedMapKey
		var cnt uint32
		iter := m.Iterate()
		for iter.Next(&key, &cnt) {
			info := ""
			if fn, ok := polM[key.FuncId]; ok {
				info = fn(key.Arg)
			}
			ch <- st.missedNotifications.MustMetric(
				float64(cnt),
				key.reason(),
				policy,
				info,
			)
		}
	}
}

func (st *state) unregisterPolicy(policy string) {
	delete(st.policies, policy)
}

func collectForDocs(_ chan<- prometheus.Metric) {
}
