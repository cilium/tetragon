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
)

// ioReaderClient implements tetragon.FineGuidanceSensors_GetEventsClient.
// ioReaderObserver implements tetragon.FineGuidanceSensorsClient interface. It reads FGS events
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

func (i *ioReaderClient) GetEvents(ctx context.Context, in *tetragon.GetEventsRequest, opts ...grpc.CallOption) (tetragon.FineGuidanceSensors_GetEventsClient, error) {
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

func (i *ioReaderClient) GetHealth(ctx context.Context, in *tetragon.GetHealthStatusRequest, opts ...grpc.CallOption) (*tetragon.GetHealthStatusResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) AddTracingPolicy(ctx context.Context, in *tetragon.AddTracingPolicyRequest, opts ...grpc.CallOption) (*tetragon.AddTracingPolicyResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) RemoveSensor(ctx context.Context, in *tetragon.RemoveSensorRequest, opts ...grpc.CallOption) (*tetragon.RemoveSensorResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) ListSensors(ctx context.Context, in *tetragon.ListSensorsRequest, opts ...grpc.CallOption) (*tetragon.ListSensorsResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) EnableSensor(ctx context.Context, in *tetragon.EnableSensorRequest, opts ...grpc.CallOption) (*tetragon.EnableSensorResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) DisableSensor(ctx context.Context, in *tetragon.DisableSensorRequest, opts ...grpc.CallOption) (*tetragon.DisableSensorResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) SetSensorConfig(ctx context.Context, in *tetragon.SetSensorConfigRequest, opts ...grpc.CallOption) (*tetragon.SetSensorConfigResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) GetSensorConfig(ctx context.Context, in *tetragon.GetSensorConfigRequest, opts ...grpc.CallOption) (*tetragon.GetSensorConfigResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) GetStackTraceTree(ctx context.Context, in *tetragon.GetStackTraceTreeRequest, opts ...grpc.CallOption) (*tetragon.GetStackTraceTreeResponse, error) {
	panic("stub")
}

func (i *ioReaderClient) GetVersion(ctx context.Context, in *tetragon.GetVersionRequest, opts ...grpc.CallOption) (*tetragon.GetVersionResponse, error) {
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
		for _, filter := range i.fieldFilters {
			filter.Filter(&res)
		}
		return &res, nil
	}
	if err := i.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (i *ioReaderClient) RuntimeHook(ctx context.Context, in *tetragon.RuntimeHookRequest, opts ...grpc.CallOption) (*tetragon.RuntimeHookResponse, error) {
	panic("stub")
}
