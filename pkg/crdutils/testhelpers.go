// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// This file contains test helpers that couldn't be included in testutils
// package because of cyclic dependencies.

package crdutils

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
