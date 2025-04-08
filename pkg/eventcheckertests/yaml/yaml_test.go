// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package yaml_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/yaml"
	"github.com/cilium/tetragon/pkg/eventcheckertests/yamlhelpers"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/stretchr/testify/assert"
)

var examplesDir string

func init() {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir = filepath.Join(filepath.Dir(filename), "../../../examples/eventchecker")
}

// Read a template file and apply data to it, returning the restulting string
func readFileTemplate(fileName string, data interface{}) (string, error) {
	templ, err := template.ParseFiles(fileName)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = templ.Execute(&buf, data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func TestExamplesSmoke(t *testing.T) {
	err := filepath.Walk(examplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip non-yaml files with a warning
		if !strings.HasSuffix(info.Name(), "yaml") || strings.HasSuffix(info.Name(), "yml") {
			logger.GetLogger().WithField("path", path).Warn("skipping non-yaml file")
			return nil
		}

		logger.GetLogger().WithField("path", path).Info("verifying file")

		// Fill this in with template data as needed
		templateData := map[string]string{
			"Pid": strconv.Itoa(os.Getpid()),
		}

		// Attempt to parse the file
		data, err := readFileTemplate(path, templateData)
		assert.NoError(t, err, "example %s must parse correctly", info.Name())

		assert.NoError(t, err)

		var conf yaml.EventCheckerConf
		yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(data), &conf)

		return nil
	})

	assert.NoError(t, err, "failed to walk examples directory")
}
