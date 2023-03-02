// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"fmt"
	"os/exec"
)

var (
	GitBinary  = "git"
	MakeBinary = "make"

	Binaries = []string{GitBinary}
)

// NB(kkourt): for now, just a single check for everything
func CheckEnvironment() error {
	for _, cmd := range Binaries {
		_, err := exec.LookPath(cmd)
		if err != nil {
			return fmt.Errorf("required cmd '%s' not found", cmd)
		}
	}

	return nil
}
