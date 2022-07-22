// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package alignchecker

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var tetragonLib string

func init() {
	flag.StringVar(&tetragonLib, "bpf-lib", filepath.Join(tus.TetragonBpfPath(), "objs"), "tetragon lib directory (location of btf file and bpf objs). Will be overridden by an TETRAGON_LIB env variable.")

	tetragonLibEnv := os.Getenv("TETRAGON_LIB")
	if tetragonLibEnv != "" {
		tetragonLib = tetragonLibEnv
	}
}

func TestStructAlignments(t *testing.T) {
	bpfObjPath := filepath.Join(tetragonLib, "bpf_alignchecker.o")
	if _, err := os.Stat(bpfObjPath); err != nil {
		t.Fatalf("Cannot check alignment against %s: %s\n", bpfObjPath, err)
	}
	if err := CheckStructAlignments(bpfObjPath); err != nil {
		t.Fatalf("C and Go structs alignment check failed: %s\n", err)
	}
}
