// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package yaml_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/yaml"
	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/eventcheckertests/yamlhelpers"
	"github.com/stretchr/testify/require"
)

func TestExamplesSmoke(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../../examples/eventchecker")

	err := filepath.Walk(examplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-yaml files
		if info.IsDir() || (!strings.HasSuffix(info.Name(), "yaml") && !strings.HasSuffix(info.Name(), "yml")) {
			return nil
		}

		// Fill this in with template data as needed
		templateData := map[string]string{
			"Pid": strconv.Itoa(os.Getpid()),
		}

		// Attempt to parse the file
		data, err := crdutils.ReadFileTemplate(path, templateData)
		require.NoError(t, err, "example %s must parse correctly", info.Name())

		var conf yaml.EventCheckerConf
		yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(data), &conf)

		return nil
	})

	require.NoError(t, err, "failed to walk examples directory")
}
