// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/stretchr/testify/assert"
)

type arrayWriter struct {
	items []string
	done  chan bool
}

func newArrayWriter(size int) *arrayWriter {
	return &arrayWriter{
		items: make([]string, 0, size),
		done:  make(chan bool),
	}
}

func (a *arrayWriter) Write(p []byte) (n int, err error) {
	a.items = append(a.items, strings.TrimSpace(string(p)))
	if len(a.items) == cap(a.items) {
		a.done <- true
	}
	return len(p), nil
}

type fakeNotifier struct {
	mux       sync.Mutex
	listeners map[server.Listener]struct{}
	removed   chan bool
}

func newFakeNotifier() *fakeNotifier {
	return &fakeNotifier{
		listeners: make(map[server.Listener]struct{}),
		removed:   make(chan bool),
	}
}

func (f *fakeNotifier) AddListener(listener server.Listener) {
	f.mux.Lock()
	f.listeners[listener] = struct{}{}
	f.mux.Unlock()
}

func (f *fakeNotifier) RemoveListener(listener server.Listener) {
	f.mux.Lock()
	delete(f.listeners, listener)
	f.removed <- true
	f.mux.Unlock()
}

func (f *fakeNotifier) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	f.mux.Lock()
	defer f.mux.Unlock()
	for l := range f.listeners {
		l.Notify(processed)
	}
}

type fakeObserver struct{}

func (f *fakeObserver) ListSensors(ctx context.Context) (*[]sensors.SensorStatus, error) {
	return nil, nil
}

func (f *fakeObserver) EnableSensor(ctx context.Context, name string) error {
	return nil
}

func (f *fakeObserver) DisableSensor(ctx context.Context, name string) error {
	return nil
}

func (f *fakeObserver) GetSensorConfig(ctx context.Context, k string, v string) (string, error) {
	return "", nil
}

func (f *fakeObserver) SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error {
	return nil
}

func (f *fakeObserver) GetTreeProto(ctx context.Context, tname string) (*tetragon.StackTraceNode, error) {
	return nil, nil
}

func (f *fakeObserver) AddTracingPolicy(ctx context.Context, sensorName string, spec *v1alpha1.TracingPolicySpec) error {
	return nil
}

func (f *fakeObserver) DelTracingPolicy(ctx context.Context, sensorName string) error {
	return nil
}

func (f *fakeObserver) RemoveSensor(ctx context.Context, sensorName string) error {
	return nil
}

func TestExporter_Send(t *testing.T) {
	eventNotifier := newFakeNotifier()
	grpcServer := server.NewServer(eventNotifier, &fakeObserver{})
	numRecords := 2
	results := newArrayWriter(numRecords)
	encoder := json.NewEncoder(results)
	ctx, cancel := context.WithCancel(context.Background())
	request := tetragon.GetEventsRequest{DenyList: []*tetragon.Filter{{BinaryRegex: []string{"b"}}}}
	exporter := NewExporter(ctx, &request, grpcServer, encoder, nil)
	exporter.Start()
	eventNotifier.NotifyListener(nil, &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Binary: "a"}},
		}})
	eventNotifier.NotifyListener(nil, &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Binary: "b"}},
		}})
	eventNotifier.NotifyListener(nil, &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Binary: "c"}},
		}})
	<-results.done
	assert.Equal(t, []string{`{"process_exec":{"process":{"binary":"a"}}}`, `{"process_exec":{"process":{"binary":"c"}}}`}, results.items)
	cancel()
	<-eventNotifier.removed
}

type jsonEvent struct {
	Event         json.RawMessage `json:"process_exec"`
	RateLimitInfo json.RawMessage `json:"rate_limit_info"`
}

const nodeName = "test-node-name"

func checkEvents(t *testing.T, eventsJSON []string, wantEvents, wantRateLimitInfo int, wantDropped uint64) {
	t.Helper()

	gotEvents, gotRateLimitInfo, gotDropped := 0, 0, uint64(0)
	for _, event := range eventsJSON {
		if event == "" {
			continue
		}

		var ev jsonEvent
		if err := json.Unmarshal([]byte(event), &ev); err != nil {
			t.Fatalf("failed to unmarshal JSON event %q: %v", event, err)
		}

		decoded := 0
		if len(ev.Event) > 0 {
			gotEvents++
			decoded++
		}
		if len(ev.RateLimitInfo) > 0 {
			var r ratelimit.InfoEvent
			if err := json.Unmarshal([]byte(event), &r); err != nil {
				t.Fatalf("failed to unmarshal JSON event %q: %v", event, err)
			}
			gotRateLimitInfo++
			gotDropped += r.RateLimitInfo.NumberOfDroppedProcessEvents
			decoded++

			if nn := r.NodeName; nn != nodeName {
				t.Errorf("unexpected node name for rate-limit-info event: got %q, want %q", nn, nodeName)
			}
		}

		if decoded != 1 {
			t.Fatalf("expected to decode %q as exactly 1 event, got %d", event, decoded)
		}
	}
	assert.Equal(t, wantEvents, gotEvents, "number of events")
	assert.Equal(t, wantRateLimitInfo, gotRateLimitInfo, "number of rate_limit_info events")
	assert.Equal(t, wantDropped, gotDropped, "number of dropped events")
}

func Test_rateLimitExport(t *testing.T) {
	// set node name to be reported in RateLimitInfo events
	hubbleNodeNameEnv := "HUBBLE_NODE_NAME"
	value, ok := os.LookupEnv(hubbleNodeNameEnv)
	if !ok || value == "" {
		if err := os.Setenv(hubbleNodeNameEnv, nodeName); err != nil {
			t.Fatalf("failed to set %s env var", hubbleNodeNameEnv)
		}
		defer os.Unsetenv(hubbleNodeNameEnv)
	}

	tests := []struct {
		name              string
		totalEvents       int
		rateLimit         int
		wantEvents        int
		wantRateLimitInfo int
		wantDropped       uint64
	}{
		{"no events", 0, 10, 0, 0, 0},
		{"rate limit", 100, 10, 10, 1, 90},
		{"rate limit all ", 100, 0, 0, 1, 100},
		{"rate limit none", 100, -1, 100, 0, 0},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s (%d events, %d rate limit)", tt.name, tt.totalEvents, tt.rateLimit), func(t *testing.T) {
			eventNotifier := newFakeNotifier()
			grpcServer := server.NewServer(eventNotifier, &fakeObserver{})
			results := newArrayWriter(tt.totalEvents)
			encoder := json.NewEncoder(results)
			ctx, cancel := context.WithCancel(context.Background())
			request := &tetragon.GetEventsRequest{}
			exporter := NewExporter(
				ctx,
				request,
				grpcServer,
				encoder,
				ratelimit.NewRateLimiter(ctx, 50*time.Millisecond, tt.rateLimit, encoder),
			)
			exporter.Start()
			for i := 0; i < tt.totalEvents; i++ {
				eventNotifier.NotifyListener(nil, &tetragon.GetEventsResponse{
					Event: &tetragon.GetEventsResponse_ProcessExec{
						ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Binary: fmt.Sprintf("a%d", i)}},
					}})
			}

			reportInterval := 100 * time.Millisecond
			// wait for ~2 report intervals to make sure we get a rate-limit-info event
			time.Sleep(2 * reportInterval)
			cancel()

			checkEvents(t, results.items, tt.wantEvents, tt.wantRateLimitInfo, tt.wantDropped)
		})
	}
}
