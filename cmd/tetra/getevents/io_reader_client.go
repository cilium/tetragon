// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	hubbleV1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ioReaderClient implements tetragon.FineGuidanceSensors_GetEventsClient.
// ioReaderObserver implements tetragon.FineGuidanceSensorsClient interface. It reads Tetragon events
type ioReaderClient struct {
	scanner      *bufio.Scanner
	allowlist    hubbleFilters.FilterFuncs
	fieldFilters []*filters.FieldFilter
	unmarshaller protojson.UnmarshalOptions
	debug        bool
	grpc.ClientStream
}

func newIOReaderClient(reader io.Reader, debug bool) *ioReaderClient {
	return &ioReaderClient{
		scanner:      bufio.NewScanner(reader),
		unmarshaller: protojson.UnmarshalOptions{DiscardUnknown: true},
		debug:        debug,
	}
}

func (i *ioReaderClient) GetEvents(ctx context.Context, in *tetragon.GetEventsRequest, _ ...grpc.CallOption) (tetragon.FineGuidanceSensors_GetEventsClient, error) {
	allowlist, err := filters.BuildFilterList(ctx, in.AllowList, filters.Filters)
	if err != nil {
		return nil, err
	}
	i.allowlist = allowlist
	i.fieldFilters = filters.FieldFiltersFromGetEventsRequest(in)
	if i.debug {
		fmt.Fprintf(os.Stderr, "DEBUG: GetEvents request: %+v\n", in)
	}
	return i, nil
}

func (i *ioReaderClient) GetHealth(_ context.Context, _ *tetragon.GetHealthStatusRequest, _ ...grpc.CallOption) (*tetragon.GetHealthStatusResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) AddTracingPolicy(_ context.Context, _ *tetragon.AddTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.AddTracingPolicyResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) DeleteTracingPolicy(_ context.Context, _ *tetragon.DeleteTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.DeleteTracingPolicyResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) ListTracingPolicies(_ context.Context, _ *tetragon.ListTracingPoliciesRequest, _ ...grpc.CallOption) (*tetragon.ListTracingPoliciesResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) RemoveSensor(_ context.Context, _ *tetragon.RemoveSensorRequest, _ ...grpc.CallOption) (*tetragon.RemoveSensorResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) ListSensors(_ context.Context, _ *tetragon.ListSensorsRequest, _ ...grpc.CallOption) (*tetragon.ListSensorsResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) EnableSensor(_ context.Context, _ *tetragon.EnableSensorRequest, _ ...grpc.CallOption) (*tetragon.EnableSensorResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) DisableSensor(_ context.Context, _ *tetragon.DisableSensorRequest, _ ...grpc.CallOption) (*tetragon.DisableSensorResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) GetStackTraceTree(_ context.Context, _ *tetragon.GetStackTraceTreeRequest, _ ...grpc.CallOption) (*tetragon.GetStackTraceTreeResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) GetVersion(_ context.Context, _ *tetragon.GetVersionRequest, _ ...grpc.CallOption) (*tetragon.GetVersionResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) Recv() (*tetragon.GetEventsResponse, error) {
	for i.scanner.Scan() {
		var res tetragon.GetEventsResponse
		line := i.scanner.Bytes()
		err := i.unmarshaller.Unmarshal(line, &res)
		if err != nil && i.debug {
			fmt.Fprintf(os.Stderr, "DEBUG: failed unmarshal: %s: %s\n", line, err)
			continue
		}
		if !hubbleFilters.Apply(i.allowlist, nil, &hubbleV1.Event{Event: &res}) {
			continue
		}
		filterEvent := &res
		if len(i.fieldFilters) > 0 && filterEvent.GetProcessExec() != nil { // this is an exec event and we have fieldFilters
			// We need a copy of the exec event as modifing the original message
			// can cause issues in the process cache (we keep a copy of that message there).
			filterEvent = proto.Clone(&res).(*tetragon.GetEventsResponse)
		}
		for _, filter := range i.fieldFilters {
			// we need not to change res
			// maybe only for exec events
			filter.Filter(filterEvent)
		}
		return filterEvent, nil
	}
	if err := i.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (i *ioReaderClient) RuntimeHook(_ context.Context, _ *tetragon.RuntimeHookRequest, _ ...grpc.CallOption) (*tetragon.RuntimeHookResponse, error) {
	panic("stub")
}
