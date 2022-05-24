// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syscallinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestSycallInfo(t *testing.T) {
	sysName := GetSyscallName(unix.SYS_BPF)
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
