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

	load = Builder("", "", "", "event", "")
	pin = linkPinPath(bpfDir, load)
	assert.Equal(t, filepath.Join(bpfDir, "event_link"), pin)

	load = Builder("", "", "", "event", "")
	load.Override = true
	pin = linkPinPath(bpfDir, load)
	assert.Equal(t, filepath.Join(bpfDir, "event_override_link"), pin)

	load = Builder("", "", "", "event", "").SetRetProbe(true)
	pin = linkPinPath(bpfDir, load)
	assert.Equal(t, filepath.Join(bpfDir, "event_return_link"), pin)

	load = Builder("", "", "", "event", "")
	pin = linkPinPath(bpfDir, load, "1_sys_exit")
	assert.Equal(t, filepath.Join(bpfDir, "event_1_sys_exit_link"), pin)
}
