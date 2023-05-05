// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"os"

	"github.com/cilium/tetragon/pkg/sensors"
)

func RemovePrograms(bpfDir, mapDir string) {
	sensors.UnloadAll()
	os.Remove(bpfDir)
	os.Remove(mapDir)
}
