// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

// ParseFilterList parses a list of process filters in JSON format into protobuf messages.
func ParseFilterList(filters string) ([]*tetragon.Filter, error) {
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
