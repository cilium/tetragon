// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !amd64 && !arm64

package elf

func parseArgs(_ *UsdtSpec) error {
	return nil
}
