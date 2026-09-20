// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"errors"
	"log/slog"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
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
