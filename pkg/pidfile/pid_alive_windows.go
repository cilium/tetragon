// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package pidfile

import (
	"os"
	"strconv"
)

func isPidAlive(pid string) bool {
	int32pid, err := strconv.ParseInt(pid, 0, 32)
	if err == nil {
		_, err = os.FindProcess(int(int32pid))
	}
	return err == nil
}
