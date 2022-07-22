// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

// t.Name() -> ExportFile
var exportFiles = make(map[string]*ExportFile, 1)
var exportFilesLock sync.Mutex

type ExportFile struct {
	*os.File
	t     *testing.T
	fName string // file name
	keep  bool   // should we keep the file at the end?
}

func (f *ExportFile) Close() error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()

	tName := f.t.Name()
	ef, ok := exportFiles[tName]
	if !ok {
		f.t.Logf("could not find ourself in exportFiles: testName=%s fname=%s", tName, f.fName)
		return f.File.Close()
	}
	if ef != f {
		f.t.Logf("Unexpected file %+v vs %+v", ef, f)
	}
	defer delete(exportFiles, tName)

	err := f.File.Close()
	if f.keep {
		f.t.Logf("keeping export file for %s (%s)", tName, ef.fName)
	} else {
		f.t.Logf("deleting export file for %s (%s)", tName, ef.fName)
		os.Remove(f.fName)
	}
	return err
}

// CreateExportFile creates an export file for a test.
// a callback will be registered at t.Cleanup() for closing the file, and removing the file
func CreateExportFile(t *testing.T) (*ExportFile, error) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()

	testName := t.Name()
	if _, ok := exportFiles[testName]; ok {
		return nil, fmt.Errorf("unexpected error: t.Name() %s already exists", testName)
	}

	fname := fmt.Sprintf("tetragon.gotest.%s.*.json", testName)
	f, err := os.CreateTemp("/tmp", fname)
	if err != nil {
		return nil, fmt.Errorf("failed to create export file for test %s: %s", t.Name(), err)
	}
	os.Chmod(f.Name(), 0644)

	ret := &ExportFile{
		File:  f,
		t:     t,
		fName: f.Name(),
		keep:  false,
	}

	exportFiles[testName] = ret
	return ret, nil
}

// GetExportFilename return export filename for test
func GetExportFilename(t *testing.T) (string, error) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := t.Name()
	ef, ok := exportFiles[testName]
	if !ok {
		return "", fmt.Errorf("file for test %s does not exist", testName)
	}
	return ef.fName, nil
}

// KeepExportFile marks export file to be kept
func KeepExportFile(t *testing.T) error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := t.Name()
	ef, ok := exportFiles[testName]
	if !ok {
		return fmt.Errorf("file for test %s does not exist", testName)
	}
	ef.keep = true
	exportFiles[testName] = ef
	return nil
}

// DontKeepExportFile: unmarks export file to be kept. This is meant for tests
// that are expected to fail.
func DontKeepExportFile(t *testing.T) error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := t.Name()
	ef, ok := exportFiles[testName]
	if !ok {
		return fmt.Errorf("file for test %s does not exist", testName)
	}
	ef.keep = false
	exportFiles[testName] = ef
	return nil
}
