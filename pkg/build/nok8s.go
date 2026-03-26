// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package build

import "testing"

func SkipIfK8sDisabled(t *testing.T) {
	t.Helper()
	t.Skip("no k8s build: test disabled")
}
