// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// GetSpecFromTemplate creates a file bsed on the given template
func GetSpecFromTemplate(
	tmplname string,
	data any,
) (string, error) {
	_, testFname, _, _ := runtime.Caller(0)
	fname := filepath.Join(filepath.Dir(testFname), "..", "..", "testdata", "specs", tmplname)
	tmpl, err := template.ParseFiles(fname)
	if err != nil {
		return "", err
	}

	tmpFilePattern := strings.TrimSuffix(tmplname, ".yaml.tmpl") + "-*.yaml"
	tmpF, err := os.CreateTemp("", tmpFilePattern)
	if err != nil {
		return "", err
	}
	tmpName := tmpF.Name()

	err = tmpl.Execute(tmpF, data)
	if err != nil {
		tmpF.Close()
		os.Remove(tmpName)
		return "", err
	}

	tmpF.Close()
	os.Chmod(tmpName, 0644)
	return tmpName, nil
}
