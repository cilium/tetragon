// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
	"github.com/cilium/tetragon/pkg/option"
)

type capSet map[tetragon.CapabilitiesType]struct{}

func newCapSet(caps []tetragon.CapabilitiesType) capSet {
	s := make(capSet, len(caps))
	for _, c := range caps {
		s[c] = struct{}{}
	}
	return s
}

func (s capSet) hasAny(caps []tetragon.CapabilitiesType) bool {
	for _, c := range caps {
		if _, ok := s[c]; ok {
			return true
		}
	}
	return false
}

func (s capSet) hasAll(caps []tetragon.CapabilitiesType) bool {
	for _, c := range caps {
		if _, ok := s[c]; !ok {
			return false
		}
	}
	return true
}

func filterSingleCapSet(caps []tetragon.CapabilitiesType, filters *tetragon.CapFilterSet) bool {
	if filters == nil {
		return true
	}

	capset := newCapSet(caps)

	if len(filters.Any) > 0 {
		return capset.hasAny(filters.Any)
	}

	if len(filters.All) > 0 {
		return capset.hasAll(filters.All)
	}

	if len(filters.Exactly) > 0 {
		return len(capset) == len(newCapSet(filters.Exactly)) && capset.hasAll(filters.Exactly)
	}

	if len(filters.None) > 0 {
		return !capset.hasAny(filters.None)
	}

	return false
}

func filterByCaps(filter *tetragon.CapFilter) (FilterFunc, error) {
	return func(ev *event.Event) bool {
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

func ensureSingleSetDefined(filter *tetragon.CapFilterSet) error {
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

func (f *CapsFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.Capabilities != nil {
		// Enable caps filter only if processCred is enabled
		if !option.Config.EnableProcessCred {
			return nil, errors.New("capabilities are not enabled in process events, cannot configure capability filter")
		}

		if err := ensureSingleSetDefined(ff.Capabilities.Permitted); err != nil {
			return nil, err
		}
		if err := ensureSingleSetDefined(ff.Capabilities.Effective); err != nil {
			return nil, err
		}
		if err := ensureSingleSetDefined(ff.Capabilities.Inheritable); err != nil {
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
