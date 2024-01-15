// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

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
			return nil, fmt.Errorf("pidSet filters use a best-effort approach for tracking PIDs and are intended for testing/development, not for production (pass the --enable-pid-set-filter to ignore)")
		}
		results = append(results, &result)
	}
	return results, nil
}

// OnBuildFilter is invoked while building a flow filter
type OnBuildFilter interface {
	OnBuildFilter(context.Context, *tetragon.Filter) ([]hubbleFilters.FilterFunc, error)
}

// OnBuildFilterFunc implements OnBuildFilter for a single function
type OnBuildFilterFunc func(context.Context, *tetragon.Filter) ([]hubbleFilters.FilterFunc, error)

// OnBuildFilter is invoked while building a flow filter
func (f OnBuildFilterFunc) OnBuildFilter(ctx context.Context, tetragonFilter *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	return f(ctx, tetragonFilter)
}

func BuildFilter(ctx context.Context, ff *tetragon.Filter, filterFuncs []OnBuildFilter) (hubbleFilters.FilterFuncs, error) {
	var fs []hubbleFilters.FilterFunc
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

func BuildFilterList(ctx context.Context, ff []*tetragon.Filter, filterFuncs []OnBuildFilter) (hubbleFilters.FilterFuncs, error) {
	filterList := make([]hubbleFilters.FilterFunc, 0, len(ff))
	for _, flowFilter := range ff {
		tf, err := BuildFilter(ctx, flowFilter, filterFuncs)
		if err != nil {
			return nil, err
		}
		filterFunc := func(ev *v1.Event) bool {
			return tf.MatchAll(ev)
		}
		filterList = append(filterList, filterFunc)
	}
	return filterList, nil
}

// Filters is the list of default filters
var Filters = []OnBuildFilter{
	&BinaryRegexFilter{},
	&HealthCheckFilter{},
	&NamespaceFilter{},
	&PidFilter{},
	&PidSetFilter{},
	&EventTypeFilter{},
	&ArgumentsRegexFilter{},
	&LabelsFilter{},
	&PodRegexFilter{},
	&PolicyNamesFilter{},
}

func GetProcess(event *v1.Event) *tetragon.Process {
	if event == nil {
		return nil
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil
	}
	return helpers.ResponseGetProcess(response)
}

func GetParent(event *v1.Event) *tetragon.Process {
	if event == nil {
		return nil
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil
	}
	return helpers.ResponseGetParent(response)
}

func GetPolicyName(event *v1.Event) string {
	if event == nil {
		return ""
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return ""
	}
	return helpers.ResponseGetProcessKprobe(response).GetPolicyName()
}
