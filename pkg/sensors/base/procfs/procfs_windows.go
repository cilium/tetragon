// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procfs

// Warning: This file is a stub and does nothing. You're probably looking for procfs_linux.go.

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func Enable() (progs []*program.Program, maps []*program.Map) {
	return
}

func Walk() error {
	return nil
}
