// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package syscallinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSycallInfo(t *testing.T) {
	abi, err := DefaultABI()
	require.NoError(t, err)
	sysName, err := GetSyscallName(abi, unix.SYS_BPF)
	require.NoError(t, err)
	if sysName != "bpf" {
		t.Fatalf("got unexpected syscall name: %s (expecting bpf)", sysName)
	}

	expectedArgs := SyscallArgs([]SyscallArgInfo{
		{Name: "cmd", Type: "int"},
		{Name: "uattr", Type: "union bpf_attr *"},
		{Name: "size", Type: "unsigned int"},
	})
	actualArgs, _ := GetSyscallArgs(sysName)
	assert.Equal(t, expectedArgs, actualArgs)
	proto := actualArgs.Proto(sysName)
	assert.Equal(t, "long bpf(int cmd, union bpf_attr * uattr, unsigned int size)", proto)
}
