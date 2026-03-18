// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tempfile

import (
	"os"
	"testing"
)

func CreateTempFile(t *testing.T, data string) string {
	file, err := os.CreateTemp(t.TempDir(), "tetragon-")
	if err != nil {
		t.Fatalf("cannot create temp. file: %v", err)
	}
	_, err = file.WriteString(data)
	if err != nil {
		t.Fatalf("cannot write to temp. file: %v", err)
	}
	err = file.Close()
	if err != nil {
		t.Fatalf("cannot close temp. file: %v", err)
	}
	return file.Name()
}
