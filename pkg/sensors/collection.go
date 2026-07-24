// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/multierr"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policystats"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type TracingPolicyState int

const (
	UnknownState TracingPolicyState = iota
	EnabledState
	DisabledState
	LoadErrorState
	ErrorState
	LoadingState
	UnloadingState
	SkippedState
	PartiallyEnabledState
)

func (s TracingPolicyState) ToTetragonState() tetragon.TracingPolicyState {
	switch s {
	case EnabledState:
		return tetragon.TracingPolicyState_TP_STATE_ENABLED
	case DisabledState:
		return tetragon.TracingPolicyState_TP_STATE_DISABLED
	case LoadErrorState:
		return tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR
	case ErrorState:
		return tetragon.TracingPolicyState_TP_STATE_ERROR
	case LoadingState:
		return tetragon.TracingPolicyState_TP_STATE_LOADING
	case UnloadingState:
		return tetragon.TracingPolicyState_TP_STATE_UNLOADING
	case SkippedState:
		return tetragon.TracingPolicyState_TP_STATE_SKIPPED
	case PartiallyEnabledState:
		return tetragon.TracingPolicyState_TP_STATE_PARTIALLY_ENABLED
	default:
		return tetragon.TracingPolicyState_TP_STATE_UNKNOWN
	}
}

// collectionKey is the unique key for sensors
// this enables policies with the same name for different namespaces
type collectionKey struct {
	name, namespace, domain string
}

func (ck *collectionKey) String() string {
	if ck.namespace != "" {
		return fmt.Sprintf("%s:%s/%s", ck.domain, ck.namespace, ck.name)
	}
	return fmt.Sprintf("%s:%s", ck.domain, ck.name)
}

func newCollectionKey(name, namespace, domain string) (collectionKey, error) {
	if domain == sensorsDomain {
		return collectionKey{}, fmt.Errorf("domain %s is reserved for internal use", domain)
	}
	return collectionKey{name, namespace, domain}, nil
}

// Exposed via ListCollections()
type Collection struct {
	Name              string
	TracingpolicyName string
	TracingpolicySpec *v1alpha1.TracingPolicySpec
	TracingpolicyMode tetragon.TracingPolicyMode
	TracingpolicyID   uint64
	PolicyfilterID    uint64
	State             TracingPolicyState
	Err               string
}

// collection is a collection of sensors
// This can either be creating from a tracing policy, or by loading sensors indepenently for sensors
// that are not loaded via a tracing policy (e.g., base sensor) and testing.
type collection struct {
	sensors []SensorIface
	name    string
	err     error
	// fields below are only set for tracing policies
	tracingpolicy   tracingpolicy.TracingPolicy
	tracingpolicyID uint64
	// if this is not zero, then the policy is filtered
	policyfilterID uint64
	// state indicates the state of the collection
	state TracingPolicyState

	warnedOnModeRetrievalFailure  atomic.Bool
	warnedOnStatsRetrievalFailure atomic.Bool
	// if non-empty, this indicates that the collection cannot be disabled, and the string is the reason why
	disableNotAllowed string
}

type selectorStatsMetadata struct {
	hook          string
	hookIndex     uint32
	selectorIndex uint32
	selectorLabel string
}

type collectionMap struct {
	// map of sensor collections: name, namespace -> collection
	c  map[collectionKey]*collection
	mu sync.RWMutex
}

func newCollectionMap() *collectionMap {
	return &collectionMap{
		c: map[collectionKey]*collection{},
	}
}

func (c *collection) info() string {
	if c.tracingpolicy != nil {
		return c.tracingpolicy.TpInfo()
	}
	return c.name
}

func (c *collection) isEnabled() bool {
	switch c.state {
	case EnabledState, PartiallyEnabledState:
		return true
	default:
		return false
	}
}

func (c *collection) getEnabledState() TracingPolicyState {
	for _, sensor := range c.sensors {
		hookStatus := sensor.HookStatus()
		for _, status := range hookStatus {
			if status.State != tetragon.HookState_STATUS_LOADED {
				return PartiallyEnabledState
			}
		}
	}
	return EnabledState
}

func (c *collection) mode() tetragon.TracingPolicyMode {
	if c.tracingpolicy == nil || !c.isEnabled() || c.isEmpty() {
		return tetragon.TracingPolicyMode_TP_MODE_UNKNOWN
	}
	mode, err := policyconf.PolicyMode(c.tracingpolicy)
	if err != nil {
		if c.warnedOnModeRetrievalFailure.CompareAndSwap(false, true) {
			logger.GetLogger().Warn("failed to retrieve policy mode", "err", err, "policy", c.name)
		}
		return tetragon.TracingPolicyMode_TP_MODE_UNKNOWN
	}

	switch mode {
	case policyconf.EnforceMode:
		return tetragon.TracingPolicyMode_TP_MODE_ENFORCE
	case policyconf.MonitorMode:
		return tetragon.TracingPolicyMode_TP_MODE_MONITOR
	case policyconf.MonitorOnlyMode:
		return tetragon.TracingPolicyMode_TP_MODE_MONITOR_ONLY
	}

	logger.GetLogger().Warn("unknown policy mode", "mode", mode)
	return tetragon.TracingPolicyMode_TP_MODE_UNKNOWN
}

func (c *collection) isEmpty() bool {
	for _, sensor := range c.sensors {
		if !sensor.IsEmpty() {
			return false
		}
	}
	return true
}

func (c *collection) stats() *tetragon.TracingPolicyStats {
	if c.tracingpolicy == nil || !c.isEnabled() || c.isEmpty() {
		return nil
	}

	stats, err := policystats.GetPolicyStats(c.tracingpolicy)
	if err != nil {
		if c.warnedOnStatsRetrievalFailure.CompareAndSwap(false, true) {
			logger.GetLogger().Warn("failed to retrieve policy stats", "err", err, "policy", c.name)
		}
		return nil
	}

	ret := &tetragon.TracingPolicyStats{
		ActionCounters: actionCountersFromStats(stats),
	}

	selectorCounters := c.selectorActionCounters()
	if len(selectorCounters) > 0 {
		ret.SelectorActionCounters = selectorCounters
	}
	return ret
}

func actionCountersFromStats(stats *policystats.PolicyStats) *tetragon.TracingPolicyActionCounters {
	return &tetragon.TracingPolicyActionCounters{
		Post:                  stats.ActionsCount[policystats.PolicyPost],
		Signal:                stats.ActionsCount[policystats.PolicySignal],
		MonitorSignal:         stats.ActionsCount[policystats.PolicyMonitorSignal],
		Override:              stats.ActionsCount[policystats.PolicyOverride],
		MonitorOverride:       stats.ActionsCount[policystats.PolicyMonitorOverride],
		NotifyEnforcer:        stats.ActionsCount[policystats.PolicyNotifyEnforcer],
		MonitorNotifyEnforcer: stats.ActionsCount[policystats.PolicyMonitorNotifyEnforcer],
		Set:                   stats.ActionsCount[policystats.PolicySet],
		MonitorSet:            stats.ActionsCount[policystats.PolicyMonitorSet],
		Nopost:                stats.ActionsCount[policystats.PolicyNoPost],
	}
}

func (c *collection) selectorActionCounters() []*tetragon.TracingPolicySelectorActionCounters {
	metadata := selectorStatsMetadataFromSpec(c.tracingpolicy.TpSpec())
	if len(metadata) == 0 {
		return nil
	}

	stats, err := policystats.GetPolicySelectorStats(c.tracingpolicy)
	if err != nil {
		if c.warnedOnStatsRetrievalFailure.CompareAndSwap(false, true) {
			logger.GetLogger().Warn("failed to retrieve policy selector stats", "err", err, "policy", c.name)
		}
		return nil
	}

	ret := make([]*tetragon.TracingPolicySelectorActionCounters, 0, len(metadata))
	for i, meta := range metadata {
		if stats[i].Empty() {
			continue
		}
		selectorIndex := meta.selectorIndex
		ret = append(ret, &tetragon.TracingPolicySelectorActionCounters{
			Hook:           meta.hook,
			HookIndex:      wrapperspb.UInt32(meta.hookIndex),
			SelectorIndex:  wrapperspb.UInt32(selectorIndex),
			SelectorLabel:  meta.selectorLabel,
			ActionCounters: actionCountersFromStats(stats[i]),
		})
	}
	return ret
}

func selectorStatsMetadataFromSpec(spec *v1alpha1.TracingPolicySpec) []selectorStatsMetadata {
	if spec == nil {
		return nil
	}

	var ret []selectorStatsMetadata
	for i, kprobe := range spec.KProbes {
		ret = appendSelectorStatsMetadata(ret, "kprobe:"+kprobe.Call, uint32(i), kprobe.Selectors)
	}
	for i, fentry := range spec.Fentries {
		ret = appendSelectorStatsMetadata(ret, "fentry:"+fentry.Call, uint32(i), fentry.Selectors)
	}
	for i, uprobe := range spec.UProbes {
		ret = appendSelectorStatsMetadata(ret, uprobeStatsHook(uprobe), uint32(i), uprobe.Selectors)
	}
	for i, tp := range spec.Tracepoints {
		ret = appendSelectorStatsMetadata(ret, "tracepoint:"+tp.Subsystem+"/"+tp.Event, uint32(i), tp.Selectors)
	}
	for i, lsm := range spec.LsmHooks {
		ret = appendSelectorStatsMetadata(ret, "lsm:"+lsm.Hook, uint32(i), lsm.Selectors)
	}
	for i, usdt := range spec.Usdts {
		ret = appendSelectorStatsMetadata(ret, "usdt:"+usdt.Path+":"+usdt.Provider+"/"+usdt.Name, uint32(i), usdt.Selectors)
	}
	return ret
}

func appendSelectorStatsMetadata(ret []selectorStatsMetadata, hook string, hookIndex uint32, selectors []v1alpha1.KProbeSelector) []selectorStatsMetadata {
	for i := range selectors {
		ret = append(ret, selectorStatsMetadata{
			hook:          hook,
			hookIndex:     hookIndex,
			selectorIndex: uint32(i),
			selectorLabel: selectors[i].Label,
		})
	}
	return ret
}

func uprobeStatsHook(spec v1alpha1.UProbeSpec) string {
	p := "uprobe:" + spec.Path
	if len(spec.Symbols) > 0 {
		p += ":" + strings.Join(spec.Symbols, ",")
	}
	if len(spec.Offsets) > 0 {
		p += ":offsets=" + uint64List(spec.Offsets)
	}
	if len(spec.Addrs) > 0 {
		p += ":addrs=" + uint64List(spec.Addrs)
	}
	return p
}

func uint64List(values []uint64) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.FormatUint(value, 10))
	}
	return strings.Join(parts, ",")
}

func policyconfMode(mode tetragon.TracingPolicyMode) (policyconf.Mode, error) {
	switch mode {
	case tetragon.TracingPolicyMode_TP_MODE_ENFORCE:
		return policyconf.EnforceMode, nil
	case tetragon.TracingPolicyMode_TP_MODE_MONITOR:
		return policyconf.MonitorMode, nil
		// we don't need to manage tetragon.TracingPolicyMode_TP_MODE_MONITOR_ONLY here.
	}

	return policyconf.InvalidMode, fmt.Errorf("unexpected mode: %v", mode)
}

func (c *collection) setMode(mode tetragon.TracingPolicyMode) error {
	if c.tracingpolicy == nil {
		return errors.New("unexpected error: setMode called in a collection that is not a tracing policy")
	}

	m, err := policyconfMode(mode)
	if err != nil {
		return err
	}

	return policyconf.SetPolicyMode(c.tracingpolicy, m)
}

// load will attempt to load a collection of sensors. If loading one of the sensors fails, it
// will attempt to unload the already loaded sensors.
func (c *collection) load(bpfDir string) error {

	var err error
	for _, sensor := range c.sensors {
		if sensor.IsLoaded() {
			// NB: For now, we don't treat a sensor already loaded as an error
			// because that would complicate things.
			continue
		}
		if err = sensor.Load(bpfDir); err != nil {
			err = fmt.Errorf("sensor %s from collection %s failed to load: %w", sensor.GetName(), c.name, err)
			break
		}
	}

	// if there was an error, try to unload all the sensors
	if err != nil {
		// NB: we could try to unload sensors going back from the one that failed, but since
		// unload() checks s.IsLoaded, is easier to just to use unload().
		if unloadErr := c.unload(true); unloadErr != nil {
			err = multierr.Append(err, fmt.Errorf("unloading after loading failure failed: %w", unloadErr))
		}
	}

	return err
}

// unload will attempt to unload all the sensors in a collection
func (c *collection) unload(unpin bool) error {
	var err error
	for _, s := range c.sensors {
		if !s.IsLoaded() {
			continue
		}
		unloadErr := s.Unload(unpin)
		err = multierr.Append(err, unloadErr)
	}

	if err != nil {
		return fmt.Errorf("failed to unload all sensors from collection %s: %w", c.name, err)
	}
	return nil
}

// destroy will attempt to destroy all the sensors in a collection
func (c *collection) destroy(unpin bool) {
	for _, s := range c.sensors {
		s.Destroy(unpin)
	}
}
