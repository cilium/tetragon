// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"os"

	"github.com/isovalent/tetragon-oss/pkg/btf"
	"github.com/isovalent/tetragon-oss/pkg/sensors"
)

func RemovePrograms(bpfDir, mapDir string) {
	sensors.UnloadAll(bpfDir)
	os.Remove(bpfDir)
	os.Remove(mapDir)
	btf.FreeCachedBTF()
}
