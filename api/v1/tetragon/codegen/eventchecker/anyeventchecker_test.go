// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
)

func TestAnyEventChecker(t *testing.T) {
	event := &tetragon.ProcessExec{Process: &tetragon.Process{Binary: "/usr/bin/modprobe"}}
	binary := func(name string) EventChecker {
		return NewProcessExecChecker("").WithProcess(NewProcessChecker().WithBinary(sm.Full(name)))
	}

	require.NoError(t, NewAnyEventChecker(binary("/bin/true"), binary("/usr/bin/modprobe")).CheckEvent(event))
	require.Error(t, NewAnyEventChecker(binary("/bin/true"), binary("/bin/false")).CheckEvent(event))
	require.Error(t, NewAnyEventChecker().CheckEvent(event))
}
