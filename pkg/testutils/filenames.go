// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/constants"
)

// t.Name() -> ExportFile
var exportFiles = make(map[string]*ExportFile, 1)
var exportFilesLock sync.Mutex

type ExportFile struct {
	*os.File
	tb         testing.TB
	fName      string // file name
	deleteFile bool   // should we delete the file at the end?
}

func fixupTestName(t testing.TB) string {
	return strings.ReplaceAll(t.Name(), "/", "-")
}

// Close() is called by the observer loop when it exits, and is responsible for deleting the file.
func (f *ExportFile) Close() error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()

	tName := fixupTestName(f.tb)
	ef, ok := lookupExportFilename(tName)
	if !ok {
		f.tb.Logf("could not find ourself in exportFiles: testName=%s fname=%s", tName, f.fName)
		return f.File.Close()
	}
	if ef != f {
		f.tb.Logf("Unexpected file %+v vs %+v", ef, f)
	}
	defer delete(exportFiles, tName)

	err := f.File.Close()
	if !f.deleteFile {
		f.tb.Logf("keeping export file for %s (%s)", tName, ef.fName)
	} else {
		f.tb.Logf("deleting export file for %s (%s)", tName, ef.fName)
		os.Remove(f.fName)
	}
	return err
}

// CreateExportFile creates an export file for a test.
// It returns an ExportFile that has a .Close() method, that will be called by the observer loop.
// This function is responsible to delete the file.
// For a file to be deleted, the tester should call DoneWithExportFile() if the test was successful.
func CreateExportFile(tb testing.TB) (*ExportFile, error) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()

	testName := fixupTestName(tb)
	if _, ok := exportFiles[testName]; ok {
		return nil, fmt.Errorf("unexpected error: t.Name() %s already exists", testName)
	}

	// Test names with / (e.g. subtests) will be rejected by os.CreateTemp due to path
	// separator in the template string. Replace / with - to avoid this.
	fname := fmt.Sprintf("tetragon.gotest.%s.*.json", testName)
	f, err := os.CreateTemp(constants.DEFAULT_TEMP_DIR, fname)
	if err != nil {
		return nil, fmt.Errorf("failed to create export file for test %s: %w", tb.Name(), err)
	}
	os.Chmod(f.Name(), 0644)

	ret := &ExportFile{
		File:       f,
		tb:         tb,
		fName:      f.Name(),
		deleteFile: false,
	}

	exportFiles[testName] = ret
	return ret, nil
}

// GetExportFilename return export filename for test
func GetExportFilename(t testing.TB) (string, error) {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := fixupTestName(t)
	ef, ok := lookupExportFilename(testName)
	if !ok {
		return "", fmt.Errorf("file for test %s does not exist", testName)
	}
	return ef.fName, nil
}

// DoneWithExportFile: marks the export file to be deleted
// It is the tester's responsibility to call this function
func DoneWithExportFile(t testing.TB) error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := fixupTestName(t)
	ef, ok := lookupExportFilename(testName)
	if !ok {
		return fmt.Errorf("file for test %s does not exist", testName)
	}
	ef.deleteFile = true
	exportFiles[testName] = ef
	return nil
}

// KeepExportFile: marks the export file to be kept
func KeepExportFile(t testing.TB) error {
	exportFilesLock.Lock()
	defer exportFilesLock.Unlock()
	testName := fixupTestName(t)
	ef, ok := lookupExportFilename(testName)
	if !ok {
		return fmt.Errorf("file for test %s does not exist", testName)
	}
	ef.deleteFile = false
	exportFiles[testName] = ef
	return nil
}

// lookupExportFilename checks if the supplied test name is in exportFiles, and if not,
// it checks if any of the ancestor tests are. If found, it returns the pointer to the
// ExportFile and an ok bool.
func lookupExportFilename(testName string) (*ExportFile, bool) {
	ef, ok := exportFiles[testName]
	if ok {
		return ef, true
	}
	for strings.Contains(testName, "-") {
		idx := strings.LastIndex(testName, "-")
		testName = testName[:idx]
		ef, ok = exportFiles[testName]
		if ok {
			return ef, true
		}
	}
	return nil, false
}
