// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
)

var (
	notSupportedWinErr = errors.New("not supported on windows")
)

// mountFS mounts the BPFFS filesystem into the desired mapRoot directory.
func mountFS(root, kind string) error {

	return notSupportedWinErr
}

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
