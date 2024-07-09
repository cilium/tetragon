// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoaderLinkPinPath(t *testing.T) {
	bpfDir := "/sys/fs/bpf/tetragon"

	var load *Program
	var pin string

	// standard link
	load = Builder("", "", "", "event", "")
	load.PinPath = "test/generic_kprobe/__x64_sys_linkat"
	pin = linkPinPath(bpfDir, load)
	assert.Equal(t, filepath.Join(bpfDir, "test/generic_kprobe/__x64_sys_linkat", "link"), pin)

	// override link
	load = Builder("", "", "", "event", "")
	load.PinPath = "test/generic_kprobe/__x64_sys_linkat"
	pin = linkPinPath(bpfDir, load, "override")
	assert.Equal(t, filepath.Join(bpfDir, "test/generic_kprobe/__x64_sys_linkat", "link_override"), pin)

	// many-kprobe link
	load = Builder("", "", "", "event", "")
	load.PinPath = "test/generic_kprobe/__x64_sys_linkat"
	pin = linkPinPath(bpfDir, load, "1_sys_exit")
	assert.Equal(t, filepath.Join(bpfDir, "test/generic_kprobe/__x64_sys_linkat", "link_1_sys_exit"), pin)
}
