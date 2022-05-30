// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

type exportFile struct {
	f     *os.File
	fname string
	keep  bool
}

// t.Name() -> file
var exportFiles = map[string]exportFile{}
var exportFilesLock sync.Mutex

// CreateExportFile creates an export file for a test.
// a callback will be registered at t.Cleanup() for closing the file, and removing the file
func CreateExportFile(t *testing.T) *os.File {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()

	testName := t.Name()
	if _, ok := exportFiles[testName]; ok {
		t.Fatalf("unexpected error: t.Name() %s is not unique", testName)
	}

	fname := fmt.Sprintf("tetragon.gotest.%s.*.json", testName)
	f, err := os.CreateTemp("/tmp", fname)
	if err != nil {
		t.Fatalf("failed to create export file for test %s: %s", t.Name(), err)
	}
	os.Chmod(f.Name(), 0644)

	exportFiles[testName] = exportFile{
		f:     f,
		fname: f.Name(),
		keep:  false,
	}

	t.Cleanup(func() {
		tname := testName
		exportFilesLock.Lock()
		defer exportFilesLock.Unlock()
		ef, ok := exportFiles[testName]
		if !ok {
			t.Fatalf("file for test %s does not exist", tname)
		}

		ef.f.Close()
		if ef.keep {
			t.Logf("keeping export file for %s (%s)", tname, ef.fname)
		} else {
			t.Logf("deleting export file for %s (%s)", tname, ef.fname)
			os.Remove(ef.fname)
		}
		delete(exportFiles, tname)
	})

	return f
}

// GetExportFilename return export filename for test
func GetExportFilename(t *testing.T) string {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := t.Name()
	ef, ok := exportFiles[testName]
	if !ok {
		t.Fatalf("file for test %s does not exist", testName)
	}
	return ef.fname
}

// KeepExportFile marks export file to be kept
func KeepExportFile(t *testing.T) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := t.Name()
	ef, ok := exportFiles[testName]
	if !ok {
		t.Fatalf("file for test %s does not exist", testName)
	}
	ef.keep = true
	exportFiles[testName] = ef
}

// DontKeepExportFile: unmarks export file to be kept. This is meant for tests
// that are expected to fail.
func DontKeepExportFile(t *testing.T) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := t.Name()
	ef, ok := exportFiles[testName]
	if !ok {
		t.Fatalf("file for test %s does not exist", testName)
	}
	ef.keep = false
	exportFiles[testName] = ef
}
