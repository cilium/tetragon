// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package alignchecker

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/require"
)

var tetragonLib string

func init() {
	flag.StringVar(&tetragonLib, "bpf-lib", filepath.Join(tus.TetragonBPFPath(), "objs"), "tetragon lib directory (location of btf file and bpf objs). Will be overridden by an TETRAGON_LIB env variable.")

	tetragonLibEnv := os.Getenv("TETRAGON_LIB")
	if tetragonLibEnv != "" {
		tetragonLib = tetragonLibEnv
	}
}

func Test_Alignments(t *testing.T) {
	bpfObjPath := filepath.Join(tetragonLib, "bpf_alignchecker.o")

	err := CheckStructAlignmentsDefault(bpfObjPath)
	require.NoError(t, err, "structs must align")
}
