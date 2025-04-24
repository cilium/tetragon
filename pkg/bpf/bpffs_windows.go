// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"github.com/cilium/tetragon/pkg/constants"
)

func CheckOrMountFS(_ string) {}

func CheckOrMountDebugFS() error {
	return constants.ErrWindowsNotSupported
}

func CheckOrMountCgroup2() error {
	return constants.ErrWindowsNotSupported
}

func ConfigureResourceLimits() error {
	return constants.ErrWindowsNotSupported
}
