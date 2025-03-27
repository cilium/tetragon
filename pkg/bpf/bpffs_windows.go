// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
)

var (
	notSupportedWinErr = errors.New("not supported on windows")
)

func CheckOrMountFS(bpfRoot string) {

}

func CheckOrMountDebugFS() error {
	return notSupportedWinErr
}

func CheckOrMountCgroup2() error {
	return notSupportedWinErr
}

func ConfigureResourceLimits() error {
	return notSupportedWinErr
}
