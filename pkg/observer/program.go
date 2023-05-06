// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"os"

	"github.com/cilium/tetragon/pkg/sensors"
)

func RemovePrograms(bpfDir string) {
	sensors.UnloadAll(bpfDir)
	os.Remove(bpfDir)
}
