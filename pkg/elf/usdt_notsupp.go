// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !linux

package elf

import "errors"

func (se *SafeELFFile) UsdtTargets() ([]*UsdtTarget, error) {
	return nil, errors.New("not supported")
}
