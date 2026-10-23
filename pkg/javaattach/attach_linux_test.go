// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaattach

import (
	"bytes"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadRequest(t *testing.T) {
	const (
		library = "/tmp/tetragon-jvmti.so"
		options = "/tmp/patch.bin"
	)
	response := "0\nreturn code: 0\n"
	conn, request := attachTestConnection(t, response)
	defer conn.Close()

	if err := loadRequest(conn, library, options); err != nil {
		t.Fatalf("loadRequest() error = %v", err)
	}
	got := <-request
	want := []string{"1", "load", library, "true", options}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Attach request fields = %#v, want %#v", got, want)
	}
}

func TestLoadRequestRejectsResponses(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantErr  string
	}{
		{name: "malformed status", response: "not-a-status\n", wantErr: "invalid Attach status"},
		{name: "Attach error", response: "13\npermission denied\n", wantErr: "status 13): permission denied"},
		{name: "agent error", response: "0\nreturn code: -1\n", wantErr: "JVMTI agent reported failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, _ := attachTestConnection(t, tt.response)
			defer conn.Close()
			err := loadRequest(conn, "/tmp/agent.so", "/tmp/options")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("loadRequest() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func attachTestConnection(t *testing.T, response string) (*net.UnixConn, <-chan []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attach.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen on test Attach socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	request := make(chan []string, 1)
	go func() {
		server, err := listener.AcceptUnix()
		if err != nil {
			request <- nil
			return
		}
		defer server.Close()
		payload, err := io.ReadAll(server)
		if err != nil {
			request <- nil
			return
		}
		fields := bytes.Split(payload, []byte{0})
		if len(fields) > 0 && len(fields[len(fields)-1]) == 0 {
			fields = fields[:len(fields)-1]
		}
		parsed := make([]string, len(fields))
		for i := range fields {
			parsed[i] = string(fields[i])
		}
		request <- parsed
		_, _ = io.WriteString(server, response)
	}()

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("connect to test Attach socket: %v", err)
	}
	return conn, request
}
