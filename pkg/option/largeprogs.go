// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !linux

package option

func EnableLargeProgs() bool {
	return false
}
