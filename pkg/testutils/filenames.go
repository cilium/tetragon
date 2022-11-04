// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// t.Name() -> ExportFile
var exportFiles = make(map[string]*ExportFile, 1)
var exportFilesLock sync.Mutex

type ExportFile struct {
	*os.File
	t          *testing.T
	fName      string // file name
	deleteFile bool   // should we delete the file at the end?
}

func fixupTestName(t *testing.T) string {
	return strings.ReplaceAll(t.Name(), "/", "-")
}

// Close() is called by the observer loop when it exits, and is responsible for deleting the file.
func (f *ExportFile) Close() error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()

	tName := fixupTestName(f.t)
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
	if !f.deleteFile {
		f.t.Logf("keeping export file for %s (%s)", tName, ef.fName)
	} else {
		f.t.Logf("deleting export file for %s (%s)", tName, ef.fName)
		os.Remove(f.fName)
	}
	return err
}

// CreateExportFile creates an export file for a test.
// It returns an ExportFile that has a .Close() method, that will be called by the observer loop.
// This function is responsible to delete the file.
// For a file to be deleted, the tester should call DoneWithExportFile() if the test was successful.
func CreateExportFile(t *testing.T) (*ExportFile, error) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()

	testName := fixupTestName(t)
	if _, ok := exportFiles[testName]; ok {
		return nil, fmt.Errorf("unexpected error: t.Name() %s already exists", testName)
	}

	// Test names with / (e.g. subtests) will be rejected by os.CreateTemp due to path
	// separator in the template string. Replace / with - to avoid this.
	fname := fmt.Sprintf("tetragon.gotest.%s.*.json", testName)
	f, err := os.CreateTemp("/tmp", fname)
	if err != nil {
		return nil, fmt.Errorf("failed to create export file for test %s: %s", t.Name(), err)
	}
	os.Chmod(f.Name(), 0644)

	ret := &ExportFile{
		File:       f,
		t:          t,
		fName:      f.Name(),
		deleteFile: false,
	}

	exportFiles[testName] = ret
	return ret, nil
}

// GetExportFilename return export filename for test
func GetExportFilename(t *testing.T) (string, error) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := fixupTestName(t)
	ef, ok := exportFiles[testName]
	if !ok {
		return "", fmt.Errorf("file for test %s does not exist", testName)
	}
	return ef.fName, nil
}

// DoneWithExportFile: marks the export file to be deleted
// It is the tester's responsibility to call this function
func DoneWithExportFile(t *testing.T) error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := fixupTestName(t)
	ef, ok := exportFiles[testName]
	if !ok {
		return fmt.Errorf("file for test %s does not exist", testName)
	}
	ef.deleteFile = true
	exportFiles[testName] = ef
	return nil
}
