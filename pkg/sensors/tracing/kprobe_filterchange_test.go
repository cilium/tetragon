// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"
)

func TestKprobeNSChanges(t *testing.T) {
	t.Skip("Deprecated FD tracking actions were removed in v1.5")
}

func TestKprobeCapChangesIn(t *testing.T) {
	t.Skip("Deprecated FD tracking actions were removed in v1.5")
}

func TestKprobeCapChangesNotIn(t *testing.T) {
	t.Skip("Deprecated FD tracking actions were removed in v1.5")
}
