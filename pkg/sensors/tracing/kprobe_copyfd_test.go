// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"
)

// Deprecated FD tracking actions were removed in v1.5.
func TestDeprecatedFDTrackingActions(t *testing.T) {
	t.Skip("Deprecated FD tracking actions were removed in v1.5")
}
