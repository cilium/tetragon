// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/event"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

type FilterFunc func(ev *event.Event) bool
type FilterFuncs []FilterFunc

// Apply filters the flow with the given white- and blacklist. Returns true
// if the flow should be included in the result.
func Apply(whitelist, blacklist FilterFuncs, ev *event.Event) bool {
	return whitelist.MatchOne(ev) && blacklist.MatchNone(ev)
}

// MatchAll returns true if all the filters match the provided data, i.e. AND.
func (fs FilterFuncs) MatchAll(ev *event.Event) bool {
	for _, f := range fs {
		if !f(ev) {
			return false
		}
	}
	return true
}

// MatchOne returns true if at least one of the filters match the provided data or
// if no filters are specified, i.e. OR.
func (fs FilterFuncs) MatchOne(ev *event.Event) bool {
	if len(fs) == 0 {
		return true
	}

	for _, f := range fs {
		if f(ev) {
			return true
		}
	}
	return false
}

// MatchNone returns true if none of the filters match the provided data or
// if no filters are specified, i.e. NOR
func (fs FilterFuncs) MatchNone(ev *event.Event) bool {
	if len(fs) == 0 {
		return true
	}

	for _, f := range fs {
		if f(ev) {
			return false
		}
	}
	return true
}

// ParseFilterList parses a list of process filters in JSON format into protobuf messages.
func ParseFilterList(filters string, enablePidSetFilters bool) ([]*tetragon.Filter, error) {
	if filters == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(filters))
	var results []*tetragon.Filter
	for {
		var result tetragon.Filter
		if err := dec.Decode(&result); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(result.PidSet) != 0 && !enablePidSetFilters {
			return nil, errors.New("pidSet filters use a best-effort approach for tracking PIDs and are intended for testing/development, not for production (pass the --enable-pid-set-filter to ignore)")
		}
		results = append(results, &result)
	}
	return results, nil
}

// OnBuildFilter is invoked while building a flow filter
type OnBuildFilter interface {
	OnBuildFilter(context.Context, *tetragon.Filter) ([]FilterFunc, error)
}

// OnBuildFilterFunc implements OnBuildFilter for a single function
type OnBuildFilterFunc func(context.Context, *tetragon.Filter) ([]FilterFunc, error)

// OnBuildFilter is invoked while building a flow filter
func (f OnBuildFilterFunc) OnBuildFilter(ctx context.Context, tetragonFilter *tetragon.Filter) ([]FilterFunc, error) {
	return f(ctx, tetragonFilter)
}

func BuildFilter(ctx context.Context, ff *tetragon.Filter, filterFuncs []OnBuildFilter) (FilterFuncs, error) {
	var fs []FilterFunc
	for _, f := range filterFuncs {
		fl, err := f.OnBuildFilter(ctx, ff)
		if err != nil {
			return nil, err
		}
		if fl != nil {
			fs = append(fs, fl...)
		}
	}
	return fs, nil
}

func BuildFilterList(ctx context.Context, ff []*tetragon.Filter, filterFuncs []OnBuildFilter) (FilterFuncs, error) {
	filterList := make([]FilterFunc, 0, len(ff))
	for _, flowFilter := range ff {
		tf, err := BuildFilter(ctx, flowFilter, filterFuncs)
		if err != nil {
			return nil, err
		}
		filterFunc := func(ev *event.Event) bool {
			return tf.MatchAll(ev)
		}
		filterList = append(filterList, filterFunc)
	}
	return filterList, nil
}

// Filters is the list of default filters
var Filters = []OnBuildFilter{
	&BinaryRegexFilter{},
	&ParentBinaryRegexFilter{},
	&AncestorBinaryRegexFilter{},
	&HealthCheckFilter{},
	&NamespaceFilter{},
	&PidFilter{},
	&PidSetFilter{},
	&EventTypeFilter{},
	&ArgumentsRegexFilter{},
	&ParentArgumentsRegexFilter{},
	&LabelsFilter{},
	&PodRegexFilter{},
	&PolicyNamesFilter{},
	&CapsFilter{},
	&ContainerIDFilter{},
	&InInitTreeFilter{},
	NewCELExpressionFilter(logger.GetLogger()),
}

func GetProcess(event *event.Event) *tetragon.Process {
	if event == nil {
		return nil
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil
	}
	return helpers.ResponseGetProcess(response)
}

func GetParent(event *event.Event) *tetragon.Process {
	if event == nil {
		return nil
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil
	}
	return helpers.ResponseGetParent(response)
}

func GetAncestors(event *event.Event) []*tetragon.Process {
	if event == nil {
		return nil
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil
	}
	return helpers.ResponseGetAncestors(response)
}

func GetPolicyName(event *event.Event) string {
	if event == nil {
		return ""
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return ""
	}

	switch ev := (response.Event).(type) {
	case *tetragon.GetEventsResponse_ProcessKprobe:
		return ev.ProcessKprobe.GetPolicyName()
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		return ev.ProcessTracepoint.GetPolicyName()
	case *tetragon.GetEventsResponse_ProcessUprobe:
		return ev.ProcessUprobe.GetPolicyName()
	case *tetragon.GetEventsResponse_ProcessLsm:
		return ev.ProcessLsm.GetPolicyName()
	default:
		return ""
	}
}

func CheckAncestorsEnabled(types []tetragon.EventType) error {
	// If no event types are specified in a filter, we assume that the filter should be applied to all of them.
	if len(types) == 0 {
		// All process event types that currently support ancestors.
		types = []tetragon.EventType{
			tetragon.EventType_PROCESS_EXEC,
			tetragon.EventType_PROCESS_EXIT,
			tetragon.EventType_PROCESS_KPROBE,
			tetragon.EventType_PROCESS_TRACEPOINT,
			tetragon.EventType_PROCESS_UPROBE,
			tetragon.EventType_PROCESS_LSM,
			tetragon.EventType_PROCESS_USDT,
		}
	}

	for _, eventType := range types {
		if !option.AncestorsEnabled(eventType) {
			return fmt.Errorf("ancestors are not enabled for %s event type, cannot configure ancestor filter", eventType)
		}
	}

	return nil
}
