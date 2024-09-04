// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
)

func TestServer(t *testing.T) {
	t.Run("GetDebug", TestGetDebug)
	t.Run("SetDebug", TestSetDebug)
}

func TestGetDebug(t *testing.T) {
	srv := &Server{}
	req := &tetragon.GetDebugRequest{Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL}
	resp, err := srv.GetDebug(context.Background(), req)
	if err != nil {
		t.Errorf("Expected GetDebug to succeed, got error %v", err)
	}
	if resp.Flag != tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL {
		t.Errorf("Expected flag in response to be %d, but got %d", tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL, resp.Flag)
	}
	expectedLogLevel := logger.GetLogLevel()
	if resp.GetLevel() != tetragon.LogLevel(expectedLogLevel) {
		t.Errorf("Expected log level in response to be %s, but got %s", expectedLogLevel.String(), resp.GetLevel().String())
	}

	// Test unknown flag
	req = &tetragon.GetDebugRequest{Flag: 42}
	resp, err = srv.GetDebug(context.Background(), req)
	if err == nil {
		t.Errorf("Expected GetDebug to fail with error for unknown flag")
	}
	if resp != nil {
		t.Errorf("Expected response to be nil for unknown flag, but got %v", resp)
	}
}

func TestSetDebug(t *testing.T) {
	srv := &Server{}
	req := &tetragon.SetDebugRequest{
		Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
		Arg: &tetragon.SetDebugRequest_Level{
			Level: tetragon.LogLevel(logrus.InfoLevel),
		},
	}
	resp, err := srv.SetDebug(context.Background(), req)
	if err != nil {
		t.Errorf("Expected SetDebug to succeed, got error %v", err)
	}
	if resp.Flag != tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL {
		t.Errorf("Expected flag in response to be %d, but got %d", tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL, resp.Flag)
	}
	expectedLogLevel := logrus.InfoLevel
	if resp.GetLevel() != tetragon.LogLevel(expectedLogLevel) {
		t.Errorf("Expected log level in response to be %s, but got %s", expectedLogLevel.String(), resp.GetLevel().String())
	}

	// Test unknown flag
	req = &tetragon.SetDebugRequest{Flag: 42}
	resp, err = srv.SetDebug(context.Background(), req)
	if err == nil {
		t.Errorf("Expected SetDebug to fail with error for unknown flag")
	}
	if resp != nil {
		t.Errorf("Expected response to be nil for unknown flag, but got %v", resp)
	}

	// Test changing log level
	prevLogLevel := logger.GetLogLevel()
	req = &tetragon.SetDebugRequest{
		Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
		Arg: &tetragon.SetDebugRequest_Level{
			Level: tetragon.LogLevel(logrus.DebugLevel),
		},
	}
	_, err = srv.SetDebug(context.Background(), req)
	if err != nil {
		t.Errorf("Expected SetDebug to succeed, got error %v", err)
	}
	newLogLevel := logger.GetLogLevel()
	if prevLogLevel == newLogLevel {
		t.Errorf("Expected log level to change, but it didn't")
	}
}
