// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package tracingpolicy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTracepointNameSchemaValidation checks the CRD pattern on
// spec.tracepoints[].subsystem and spec.tracepoints[].event, which keeps path
// separators and ".." out of the tracefs format path and the pin path.
func TestTracepointNameSchemaValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		subsystem string
		event     string
		wantErr   bool
	}{
		{name: "valid", subsystem: "syscalls", event: "sys_enter_openat"},
		// raw tracepoints such as 9p/9p_client_req start with a digit
		{name: "leading digit", subsystem: "9p", event: "9p_client_req"},
		{name: "dash", subsystem: "sub-sys", event: "some-event"},
		{name: "leading underscore", subsystem: "_underscore", event: "_underscore"},
		{name: "empty subsystem", subsystem: "", event: "sys_enter_openat", wantErr: true},
		{name: "empty event", subsystem: "syscalls", event: "", wantErr: true},
		{name: "slash in subsystem", subsystem: "syscalls/evil", event: "sys_enter_openat", wantErr: true},
		{name: "slash in event", subsystem: "syscalls", event: "evil/sys_enter_openat", wantErr: true},
		{name: "dotdot in subsystem", subsystem: "../../etc", event: "passwd", wantErr: true},
		{name: "dotdot in event", subsystem: "syscalls", event: "..", wantErr: true},
		{name: "leading dash in subsystem", subsystem: "-syscalls", event: "sys_enter_openat", wantErr: true},
		{name: "colon in event", subsystem: "syscalls", event: "sys:enter", wantErr: true},
		{name: "space in subsystem", subsystem: "sys calls", event: "sys_enter_openat", wantErr: true},
		{name: "nul in event", subsystem: "syscalls", event: "sys_enter\x00", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromYAML(fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: tracepoint-names
spec:
  tracepoints:
  - subsystem: %q
    event: %q
`, tc.subsystem, tc.event))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
