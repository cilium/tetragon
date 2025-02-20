// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"

	hubbleV1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleFilters "github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/filters"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

// ioReaderClient implements tetragon.FineGuidanceSensors_GetEventsClient.
// ioReaderObserver implements tetragon.FineGuidanceSensorsClient interface. It reads Tetragon events
type ioReaderClient struct {
	scanner      *bufio.Scanner
	allowlist    hubbleFilters.FilterFuncs
	fieldFilters []*fieldfilters.FieldFilter
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
	ffs, err := fieldfilters.FieldFiltersFromGetEventsRequest(in)
	if err != nil {
		return nil, fmt.Errorf("failed to create field filters: %w", err)
	}
	i.allowlist = allowlist
	i.fieldFilters = ffs
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

func (i *ioReaderClient) EnableTracingPolicy(_ context.Context, _ *tetragon.EnableTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.EnableTracingPolicyResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) DisableTracingPolicy(_ context.Context, _ *tetragon.DisableTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.DisableTracingPolicyResponse, error) {
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
		res := &tetragon.GetEventsResponse{}
		line := i.scanner.Bytes()
		err := i.unmarshaller.Unmarshal(line, res)
		if err != nil && i.debug {
			fmt.Fprintf(os.Stderr, "DEBUG: failed unmarshal: %s: %s\n", line, err)
			continue
		}
		if !hubbleFilters.Apply(i.allowlist, nil, &hubbleV1.Event{Event: res}) {
			continue
		}
		for _, filter := range i.fieldFilters {
			res, err = filter.Filter(res)
			if err != nil {
				return nil, err
			}
		}
		return res, nil
	}
	if err := i.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (i *ioReaderClient) RuntimeHook(_ context.Context, _ *tetragon.RuntimeHookRequest, _ ...grpc.CallOption) (*tetragon.RuntimeHookResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) GetDebug(_ context.Context, _ *tetragon.GetDebugRequest, _ ...grpc.CallOption) (*tetragon.GetDebugResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) SetDebug(_ context.Context, _ *tetragon.SetDebugRequest, _ ...grpc.CallOption) (*tetragon.SetDebugResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) ConfigureTracingPolicy(_ context.Context, _ *tetragon.ConfigureTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.ConfigureTracingPolicyResponse, error) {
	panic("stub")
}
