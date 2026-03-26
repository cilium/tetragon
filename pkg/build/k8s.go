// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package build

import "testing"

func SkipIfK8sDisabled(_ *testing.T) {
}
