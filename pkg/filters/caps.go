// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"errors"
	"fmt"
	"strings"

	hubbleV1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleFilters "github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/option"
	mapset "github.com/deckarep/golang-set/v2"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func filterSingleCapSet(caps []tetragon.CapabilitiesType, filters *tetragon.CapFilterSet) bool {
	if filters == nil {
		return true
	}

	filterset := mapset.NewSet[tetragon.CapabilitiesType]()

	capset := mapset.NewSet[tetragon.CapabilitiesType]()
	capset.Append(caps...)

	if len(filters.Any) > 0 {
		filterset.Append(filters.Any...)
		return capset.ContainsAny(filterset.ToSlice()...)
	}

	if len(filters.All) > 0 {
		filterset.Append(filters.All...)
		return capset.Intersect(filterset).Equal(filterset)
	}

	if len(filters.Exactly) > 0 {
		filterset.Append(filters.Exactly...)
		return capset.Equal(filterset)
	}

	if len(filters.None) > 0 {
		filterset.Append(filters.None...)
		return capset.Intersect(filterset).IsEmpty()
	}

	return false
}

func filterByCaps(filter *tetragon.CapFilter) (hubbleFilters.FilterFunc, error) {
	return func(ev *hubbleV1.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		caps := process.Cap
		if caps == nil {
			return false
		}

		return filterSingleCapSet(caps.Effective, filter.Effective) &&
			filterSingleCapSet(caps.Inheritable, filter.Inheritable) &&
			filterSingleCapSet(caps.Permitted, filter.Permitted)
	}, nil
}

type CapsFilter struct{}

func ensure_single_set_defined(filter *tetragon.CapFilterSet) error {
	if filter == nil {
		return nil
	}
	defined := []string{}
	filter.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if v.Interface() == nil {
			return true
		}
		defined = append(defined, string(fd.Name()))
		return true
	})
	if len(defined) > 1 {
		return fmt.Errorf("capability filter may only define one match set, got: %s", strings.Join(defined[:], ", "))
	}
	if len(defined) == 0 {
		return errors.New("capability filter must define exactly one match set")
	}
	return nil
}

func (f *CapsFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.Capabilities != nil {
		// Enable caps filter only if processCred is enabled
		if !option.Config.EnableProcessCred {
			return nil, errors.New("capabilities are not enabled in process events, cannot configure capability filter")
		}

		if err := ensure_single_set_defined(ff.Capabilities.Permitted); err != nil {
			return nil, err
		}
		if err := ensure_single_set_defined(ff.Capabilities.Effective); err != nil {
			return nil, err
		}
		if err := ensure_single_set_defined(ff.Capabilities.Inheritable); err != nil {
			return nil, err
		}

		capFilters, err := filterByCaps(ff.Capabilities)
		if err != nil {
			return nil, err
		}
		fs = append(fs, capFilters)
	}
	return fs, nil
}
