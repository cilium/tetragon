// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package pidfile

import (
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/option"
)

func isPidAlive(pid string) bool {
	_, err := os.Stat(filepath.Join(option.Config.ProcFS, pid))
	return err == nil
}
