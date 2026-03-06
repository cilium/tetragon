// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/cilium/tetragon/pkg/config"
)

func checkFentry(t *testing.T) {
	if !config.EnableV61Progs() {
		t.Skip("fentry requires at least 6.1 kernel")
	}
}

func TestFentryObjectLoad(t *testing.T) {
	checkFentry(t)
	testKprobeObjectLoad(t, true)
}
