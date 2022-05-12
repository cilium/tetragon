// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {

	tmpFile, err := ioutil.TempFile(os.TempDir(), "fgs-bugtool-test-")
	if err != nil {
		t.Error("failed to create temporary file")
	}
	defer os.Remove(tmpFile.Name())

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
