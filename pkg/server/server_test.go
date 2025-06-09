// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"log/slog"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/stretchr/testify/require"
)

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
