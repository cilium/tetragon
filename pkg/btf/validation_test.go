// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows
// +build !windows

package btf

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/require"
)

func expectError(t *testing.T, err error) error {
	if err == nil {
		return errors.New("validation should have failed, but did not")
	}
	// NB: eventually it would be good if we check that the error the
	// specific error we expect. For now, we just print the erorr so that
	// we can  inspect it.
	t.Logf("Got an error as expected: %s", err)
	return nil
}
func expectOK(_ *testing.T, err error) error {
	if err != nil {
		return err
	}
	return nil
}

var testFiles = []struct {
	specFname string
	checkFn   func(t *testing.T, err error) error
}{
	{specFname: "specs/nosuchcall.yaml", checkFn: expectError},
	{specFname: "specs/notasyscall.yaml", checkFn: expectError},
	{specFname: "specs/syswrongargindex.yaml", checkFn: expectError},
	{specFname: "specs/syswrongargtype.yaml", checkFn: expectError},
	{specFname: "specs/syslseek.yaml", checkFn: expectOK},
	{specFname: "specs/wrongargindex.yaml", checkFn: expectError},
	{specFname: "specs/wrongargtype.yaml", checkFn: expectError},
	{specFname: "specs/lseek.yaml", checkFn: expectOK},
	/* {specFname: "specs/wrongrettype.yaml", checkFn: expectError}, */
	/* {specFname: "specs/wrongrettype.yaml", checkFn: expectError}, */
}

func genericTestSpecs(ks *ksyms.Ksyms, testdataPath string, btfFName string) func(*testing.T) {
	return func(t *testing.T) {
		if _, err := os.Stat(btfFName); err != nil {
			t.Skipf("%q not found", btfFName)
		}
		btf, err := btf.LoadSpec(btfFName)
		if err != nil {
			t.Fatalf("failed to initialize BTF: %s", err)
		}

		for fi := range testFiles {
			specFname := testFiles[fi].specFname
			t.Run(specFname, func(t *testing.T) {
				specFname := filepath.Join(testdataPath, specFname)
				tp, err := tracingpolicy.FromFile(specFname)
				if err != nil {
					t.Fatal(err)
				}
				spec := tp.TpSpec()
				for ki := range spec.KProbes {
					err = ValidateKprobeSpec(btf, spec.KProbes[ki].Call, &spec.KProbes[ki], ks)
					if checkErr := testFiles[fi].checkFn(t, err); checkErr != nil {
						t.Fatal(checkErr)
					}
				}
			})
		}
	}
}

func TestSpecs(t *testing.T) {
	_, testFname, _, _ := runtime.Caller(0)
	testdataPath := filepath.Join(filepath.Dir(testFname), "..", "..", "testdata")

	// get kernel symbols
	ks, err := ksyms.KernelSymbols()
	if err != nil {
		t.Fatalf("validateKprobeSpec: ksyms.KernelSymbols: %s", err)
	}

	btfFiles, err := listBtfFiles()
	fatalOnError(t, err)

	for _, btfFile := range btfFiles {
		// An extra "/" is added to enhance test name readability
		t.Run(btfFile+"/", genericTestSpecs(ks, testdataPath, btfFile))
	}
}

func TestEnum(t *testing.T) {
	require.Equal(t,
		getKernelType(&btf.Enum{
			Size:   2,
			Signed: false,
		}), "u16")
	require.Equal(t,
		getKernelType(&btf.Enum{
			Size:   4,
			Signed: true,
		}), "s32")
}
