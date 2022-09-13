// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

import (
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSaveAndLoad(t *testing.T) {

	tmpFile, err := os.CreateTemp(t.TempDir(), "tetragon-bugtool-test-")
	if err != nil {
		t.Error("failed to create temporary file")
	}
	defer assert.NoError(t, tmpFile.Close())

	info1 := InitInfo{
		ExportFname: "1",
		LibDir:      "2",
		BtfFname:    "3",
		ServerAddr:  "",
		MetricsAddr: "foo",
	}

	if err := doSaveInitInfo(tmpFile.Name(), &info1); err != nil {
		t.Errorf("failed to save info: %s", err)
	}

	info2, err := doLoadInitInfo(tmpFile.Name())
	if err != nil {
		t.Errorf("failed to load info: %s", err)
	}

	if !reflect.DeepEqual(&info1, info2) {
		t.Errorf("mismatching structures: %s vs %s", info1, info2)
	}

	t.Log("Success")
}
