// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func InteractiveWait(t *testing.T) {
	dir, err := os.MkdirTemp("", strings.ToLower(t.Name())+"-wait-*")
	require.NoError(t, err)

	filename := path.Join(dir, "continue")
	t.Logf("waiting for file %s to appear", filename)
	for {
		if _, err := os.Stat(filename); errors.Is(err, fs.ErrNotExist) {
			time.Sleep(1 * time.Second)
			continue
		}
		os.Remove(filename)
		os.Remove(dir)
		break
	}
}
