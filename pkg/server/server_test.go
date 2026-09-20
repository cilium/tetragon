// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policystore"
)

type testEventFieldFilter func(*tetragon.GetEventsResponse) (*tetragon.GetEventsResponse, error)

func (f testEventFieldFilter) Filter(event *tetragon.GetEventsResponse) (*tetragon.GetEventsResponse, error) {
	return f(event)
}

func eventWithArguments(arguments string) *tetragon.GetEventsResponse {
	return &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{Arguments: arguments},
			},
		},
	}
}

func redactArguments(event *tetragon.GetEventsResponse) (*tetragon.GetEventsResponse, error) {
	return eventWithArguments("[redacted]"), nil
}

func TestApplyFieldFilters(t *testing.T) {
	errFilter := errors.New("field filter failed")
	tests := []struct {
		name            string
		filters         []testEventFieldFilter
		wantArguments   string
		wantErr         error
		wantNilResponse bool
	}{
		{
			name:          "normal filtering",
			filters:       []testEventFieldFilter{redactArguments},
			wantArguments: "[redacted]",
		},
		{
			name: "first filter fails",
			filters: []testEventFieldFilter{func(event *tetragon.GetEventsResponse) (*tetragon.GetEventsResponse, error) {
				return nil, errFilter
			}},
			wantErr:         errFilter,
			wantNilResponse: true,
		},
		{
			name: "later filter fails",
			filters: []testEventFieldFilter{
				redactArguments,
				func(event *tetragon.GetEventsResponse) (*tetragon.GetEventsResponse, error) {
					return nil, errFilter
				},
			},
			wantErr:         errFilter,
			wantNilResponse: true,
		},
		{
			name: "multiple filters succeed",
			filters: []testEventFieldFilter{
				redactArguments,
				func(event *tetragon.GetEventsResponse) (*tetragon.GetEventsResponse, error) {
					return eventWithArguments(event.GetProcessExec().GetProcess().GetArguments() + " twice"), nil
				},
			},
			wantArguments: "[redacted] twice",
		},
		{
			name:          "no filters",
			wantArguments: "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := applyFieldFilters(eventWithArguments("secret"), tt.filters)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantNilResponse {
				require.Nil(t, filtered)
				return
			}
			require.Equal(t, tt.wantArguments, filtered.GetProcessExec().GetProcess().GetArguments())
		})
	}
}

type testNotifier struct {
	mu       sync.Mutex
	listener Listener
	removed  chan struct{}
}

func newTestNotifier() *testNotifier {
	return &testNotifier{removed: make(chan struct{})}
}

func (n *testNotifier) AddListener(listener Listener) {
	n.mu.Lock()
	n.listener = listener
	n.mu.Unlock()
}

func (n *testNotifier) RemoveListener(listener Listener) {
	n.mu.Lock()
	if n.listener == listener {
		n.listener = nil
	}
	n.mu.Unlock()
	close(n.removed)
}

func (n *testNotifier) NotifyListener(_ any, event *tetragon.GetEventsResponse) {
	n.mu.Lock()
	listener := n.listener
	n.mu.Unlock()
	listener.Notify(event)
}

type testGetEventsServer struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *tetragon.GetEventsResponse
}

func (s *testGetEventsServer) Context() context.Context {
	return s.ctx
}

func (s *testGetEventsServer) Send(event *tetragon.GetEventsResponse) error {
	s.sent <- event
	return nil
}

func TestGetEventsListenerFieldFilterFailure(t *testing.T) {
	failingFilter := &tetragon.FieldFilter{
		Fields: &fieldmaskpb.FieldMask{Paths: []string{"process.arguments"}},
		Action: tetragon.FieldFilterAction_EXCLUDE,
	}
	tests := []struct {
		name        string
		filters     []*tetragon.FieldFilter
		aggregation *tetragon.AggregationOptions
	}{
		{
			name:    "first filter fails",
			filters: []*tetragon.FieldFilter{failingFilter},
		},
		{
			name: "later filter fails",
			filters: []*tetragon.FieldFilter{
				{
					EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_EXIT},
					Fields:   &fieldmaskpb.FieldMask{Paths: []string{"process.arguments"}},
					Action:   tetragon.FieldFilterAction_EXCLUDE,
				},
				failingFilter,
			},
		},
		{
			name:        "aggregation",
			filters:     []*tetragon.FieldFilter{failingFilter},
			aggregation: &tetragon.AggregationOptions{ChannelBufferSize: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &tetragon.GetEventsRequest{
				FieldFilters:       tt.filters,
				AggregationOptions: tt.aggregation,
			}
			event := &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessExec{},
				NodeName: "must-not-be-sent",
			}
			filters, err := fieldfilters.FieldFiltersFromGetEventsRequest(request)
			require.NoError(t, err)
			partial, err := filters[len(filters)-1].Filter(event)
			require.Error(t, err)
			require.NotNil(t, partial)
			require.NotSame(t, event, partial)

			notifier := newTestNotifier()
			var cleanupWG sync.WaitGroup
			serverCtx, cancelServer := context.WithCancel(t.Context())
			defer cancelServer()
			stream := &testGetEventsServer{
				ctx:  t.Context(),
				sent: make(chan *tetragon.GetEventsResponse, 1),
			}
			srv := NewServer(serverCtx, &cleanupWG, notifier, nil, nil, nil)
			run, err := srv.GetEventsListener(request, stream, nil)
			require.NoError(t, err)

			result := make(chan error, 1)
			go func() {
				result <- run()
			}()
			notifier.NotifyListener(nil, event)

			select {
			case err := <-result:
				require.ErrorContains(t, err, "failed to apply field filter")
			case <-time.After(time.Second):
				t.Fatal("GetEventsListener did not return after field filter failure")
			}
			select {
			case sent := <-stream.sent:
				t.Fatalf("field filter failure delivered event: %v", sent)
			default:
			}
			select {
			case <-notifier.removed:
			case <-time.After(time.Second):
				t.Fatal("GetEventsListener did not remove listener")
			}
			cleanupWG.Wait()
		})
	}
}

func TestServer(t *testing.T) {
	t.Run("GetDebug", TestGetDebug)
	t.Run("SetDebug", TestSetDebug)
}

func TestGetDebug(t *testing.T) {
	srv := &Server{}
	req := &tetragon.GetDebugRequest{Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL}
	resp, err := srv.GetDebug(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL, resp.Flag)
	require.Equal(t, toTetragonLogLevel(logger.GetLogLevel(logger.GetLogger())).String(), resp.GetLevel().String())

	// Test unknown flag
	req = &tetragon.GetDebugRequest{Flag: 42}
	resp, err = srv.GetDebug(t.Context(), req)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestSetDebug(t *testing.T) {
	srv := &Server{}
	req := &tetragon.SetDebugRequest{
		Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
		Arg: &tetragon.SetDebugRequest_Level{
			Level: tetragon.LogLevel_LOG_LEVEL_INFO,
		},
	}
	resp, err := srv.SetDebug(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL, req.Flag)
	require.Equal(t, int(toTetragonLogLevel(slog.LevelInfo)), int(resp.GetLevel()))

	// Test unknown flag
	req = &tetragon.SetDebugRequest{Flag: 42}
	resp, err = srv.SetDebug(t.Context(), req)
	require.Error(t, err, "Expected SetDebug to fail with error for unknown flag")
	require.Nil(t, resp, "Expected response to be non-nil for unknown flag")

	// Test changing log level
	prevLogLevel := logger.GetLogLevel(logger.GetLogger())
	req = &tetragon.SetDebugRequest{
		Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
		Arg: &tetragon.SetDebugRequest_Level{
			Level: tetragon.LogLevel_LOG_LEVEL_DEBUG,
		},
	}
	_, err = srv.SetDebug(t.Context(), req)
	require.NoError(t, err, "Expected SetDebug to succeed with valid log level")
	require.NotEqual(t, logger.GetLogLevel(logger.GetLogger()), prevLogLevel, "Expected log level to change, but it didn't")
}

func TestConfigureTracingPolicyStoresModeInYAML(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("policy store filenames are not supported on Windows")
	}

	store, err := policystore.OpenAndLoad(t.TempDir())
	require.NoError(t, err)
	id := policystore.PolicyID{Name: "test-policy", Namespace: "", Domain: GrpcDomain}
	state := policystore.PolicyWithState{
		YAML: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: test-policy
spec:
  options:
  - name: policy-mode
    value: enforce
`,
		Enabled: true,
	}
	require.NoError(t, store.Put(id, state))

	enabled := false
	mode := tetragon.TracingPolicyMode_TP_MODE_MONITOR
	srv := &Server{observer: &FakeObserver{}, policyStore: store}
	_, err = srv.ConfigureTracingPolicy(t.Context(), &tetragon.ConfigureTracingPolicyRequest{
		Name:   "test-policy",
		Enable: &enabled,
		Mode:   &mode,
	})
	require.NoError(t, err)
	state, exists := store.Get(id)
	require.True(t, exists)
	require.False(t, state.Enabled)
	require.YAMLEq(t, `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: test-policy
spec:
  options:
  - name: policy-mode
    value: monitor
`, state.YAML)
}
