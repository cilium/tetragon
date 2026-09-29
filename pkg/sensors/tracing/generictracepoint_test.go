// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestPreValidateTracepointName(t *testing.T) {
	tests := []struct {
		subsys string
		event  string
		valid  bool
	}{
		{"raw_syscalls", "sys_enter", true},
		{"intel-sst", "sst_ipc_msg_tx", true},
		{"_underscore", "_underscore", true},
		// Leading digits are refused by validIdentifier(), but raw
		// tracepoints never reach it and these names are attachable.
		{"9p", "9p_client_req", true},

		{"", "sys_enter", false},
		{"raw_syscalls", "", false},
		{"..", "..", false},
		{"../../../etc", "passwd", false},
		{"raw_syscalls", "../../../etc/passwd", false},
		{"raw/syscalls", "sys_enter", false},
		{"raw_syscalls", "sys/enter", false},
		{"raw_syscalls", "sys enter", false},
		{"raw_syscalls", "sys_enter\x00", false},
	}

	for _, test := range tests {
		// Raw skips loading the tracefs format file, so the valid cases do
		// not depend on the tracepoint existing on the test machine.
		spec := v1alpha1.TracepointSpec{
			Subsystem: test.subsys,
			Event:     test.event,
			Raw:       true,
		}
		_, err := preValidateTracepoint(&spec)
		if test.valid {
			require.NoError(t, err, "%q/%q", test.subsys, test.event)
		} else {
			require.Error(t, err, "%q/%q", test.subsys, test.event)
		}
	}
}
