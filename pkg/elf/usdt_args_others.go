// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build (!amd64 && !arm64) || !linux

package elf

func parseArgs(_ *UsdtSpec) error {
	return nil
}
