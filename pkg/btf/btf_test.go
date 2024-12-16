// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	btf "github.com/cilium/ebpf/btf"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var testBtfFiles = []struct {
	btf     string
	create  string
	wantbtf string
	err     error
}{
	{"", "", defaults.DefaultBTFFile, nil},
	{defaults.DefaultBTFFile, "", defaults.DefaultBTFFile, nil},
	{"invalid-btf-file", "", "", fmt.Errorf("BTF file 'invalid-btf-file' does not exist should fail")},
	{"valid-btf-file", "valid-btf-file", "valid-btf-file", nil},
}

func setupfiles() func(*testing.T, string, ...string) {
	return func(t *testing.T, param string, files ...string) {
		for _, f := range files {
			if param == "create" {
				h, e := os.Create(f)
				assert.NoError(t, e)
				h.Close()
			} else if param == "remove" {
				os.Remove(f)
			}
		}
	}
}

func TestObserverFindBTF(t *testing.T) {
	tmpdir := t.TempDir()

	old := os.Getenv("TETRAGON_BTF")
	defer os.Setenv("TETRAGON_BTF", old)

	handlefiles := setupfiles()
	for _, test := range testBtfFiles {
		if test.create != "" {
			handlefiles(t, "create", test.create, filepath.Join(tmpdir, test.create))
			defer handlefiles(t, "remove", test.create, filepath.Join(tmpdir, test.create))
		}

		_, err := os.Stat(defaults.DefaultBTFFile)
		if err != nil && test.wantbtf == defaults.DefaultBTFFile {
			continue
		}

		btf, err := observerFindBTF(tmpdir, test.btf)
		if test.err != nil {
			assert.Errorf(t, err, "observerFindBTF() on '%s'  -  want:%v  -  got:no error", test.btf, test.err)
			continue
		}
		assert.NoErrorf(t, err, "observerFindBTF() on '%s'  - want:no error  -  got:%v", test.btf, err)
		assert.Equalf(t, test.wantbtf, btf, "observerFindBTF() on '%s'  -  want:'%s'  -  got:'%s'", test.btf, test.wantbtf, btf)

		// Test now without lib set
		btf, err = observerFindBTF("", test.btf)
		if test.err != nil {
			assert.Errorf(t, err, "observerFindBTF() on '%s'  -  want:%v  -  got:no error", test.btf, test.err)
			continue
		}
		assert.NoErrorf(t, err, "observerFindBTF() on '%s'  -   want:no error  -  got:%v", test.btf, err)
		assert.Equalf(t, test.wantbtf, btf, "observerFindBTF() on '%s'  -  want:'%s'  -  got:'%s'", test.btf, test.wantbtf, btf)
	}
}

func TestObserverFindBTFEnv(t *testing.T) {
	old := os.Getenv("TETRAGON_BTF")
	defer os.Setenv("TETRAGON_BTF", old)

	lib := defaults.DefaultTetragonLib
	btffile := defaults.DefaultBTFFile
	_, err := os.Stat(btffile)
	if err != nil {
		/* No default vmlinux file */
		btf, err := observerFindBTF("", "")
		if old != "" {
			assert.NoError(t, err)
			assert.NotEmpty(t, btf)
		} else {
			assert.Error(t, err)
			assert.Empty(t, btf)
		}
		/* Let's clear up environment vars */
		os.Setenv("TETRAGON_BTF", "")
		btf, err = observerFindBTF("", "")
		assert.Error(t, err)
		assert.Empty(t, btf)

		/* Let's try provided path to lib but tests put the btf inside /boot/ */
		btf, err = observerFindBTF(lib, "")
		assert.Error(t, err)
		assert.Empty(t, btf)

		/* Let's try out the btf file that is inside /boot/ */
		var uname unix.Utsname
		err = unix.Uname(&uname)
		assert.NoError(t, err)
		kernelVersion := unix.ByteSliceToString(uname.Release[:])
		os.Setenv("TETRAGON_BTF", filepath.Join("/boot/", fmt.Sprintf("btf-%s", kernelVersion)))
		btf, err = observerFindBTF(lib, "")
		assert.NoError(t, err)
		assert.NotEmpty(t, btf)

		btffile = btf
		err = os.Setenv("TETRAGON_BTF", btffile)
		assert.NoError(t, err)
		btf, err = observerFindBTF(lib, "")
		assert.NoError(t, err)
		assert.Equal(t, btffile, btf)
	} else {
		btf, err := observerFindBTF("", "")
		assert.NoError(t, err)
		assert.Equal(t, btffile, btf)

		err = os.Setenv("TETRAGON_BTF", btffile)
		assert.NoError(t, err)
		btf, err = observerFindBTF(lib, "")
		assert.NoError(t, err)
		assert.Equal(t, btffile, btf)
	}

	/* Following should fail */
	err = os.Setenv("TETRAGON_BTF", "invalid-btf-file")
	assert.NoError(t, err)
	btf, err := observerFindBTF(lib, "")
	assert.Error(t, err)
	assert.Equal(t, "", btf)
}

func TestInitCachedBTF(t *testing.T) {
	_, err := os.Stat(defaults.DefaultBTFFile)
	if err != nil {
		btffile := os.Getenv("TETRAGON_BTF")
		err = InitCachedBTF(defaults.DefaultTetragonLib, "")
		if btffile != "" {
			assert.NoError(t, err)
			file := GetCachedBTFFile()
			assert.EqualValues(t, btffile, file, "GetCachedBTFFile()  -  want:'%s'  - got:'%s'", btffile, file)
		} else {
			assert.Error(t, err)
		}
	} else {
		err = InitCachedBTF(defaults.DefaultTetragonLib, "")
		assert.NoError(t, err)

		btffile := GetCachedBTFFile()
		assert.EqualValues(t, defaults.DefaultBTFFile, btffile, "GetCachedBTFFile()  -  want:'%s'  - got:'%s'", defaults.DefaultBTFFile, btffile)
	}
}

func testFindNextBtf(t *testing.T, spec *btf.Spec, rootTypeStr string, strPath string) (*[api.MaxBtfArgDepth]api.ConfigBtfArg, *btf.Type, error) {
	var btfArgs [api.MaxBtfArgDepth]api.ConfigBtfArg
	path := strings.Split(strPath, ".")

	rootType, err := spec.AnyTypeByName(rootTypeStr)
	if err != nil {
		assert.Error(t, err)
	}
	lastBtfType, err := FindNextBtfType(&btfArgs, rootType, path, 0)
	if err != nil {
		return nil, nil, err
	}

	return &btfArgs, lastBtfType, nil
}

func testAssertEqualPath(t *testing.T, spec *btf.Spec, rootTypeStr string, strPath string, resBtfArgs []api.ConfigBtfArg) {
	var btfArgsToVerify [api.MaxBtfArgDepth]api.ConfigBtfArg

	for i, item := range resBtfArgs {
		if i < api.MaxBtfArgDepth {
			btfArgsToVerify[i] = item
		}
	}

	btfArgs, _, err := testFindNextBtf(t, spec, rootTypeStr, strPath)

	assert.NoError(t, err)
	assert.Equal(t, *btfArgs, btfArgsToVerify)
}

func testAssertEqualBtfPath(t *testing.T, spec *btf.Spec) {
	// Test default behaviour
	testAssertEqualPath(
		t,
		spec,
		"linux_binprm",
		"file.f_path.dentry.d_name.name",
		[]api.ConfigBtfArg{
			{Offset: 64, IsPointer: 1, IsInitialized: 1},
			{Offset: 152, IsPointer: 0, IsInitialized: 1},
			{Offset: 8, IsPointer: 1, IsInitialized: 1},
			{Offset: 32, IsPointer: 0, IsInitialized: 1},
			{Offset: 8, IsPointer: 1, IsInitialized: 1},
		})

	// Test anonymous struct
	testAssertEqualPath(
		t,
		spec,
		"linux_binprm",
		"mm.arg_start",
		[]api.ConfigBtfArg{
			{Offset: 16, IsPointer: 1, IsInitialized: 1},
			{Offset: 368, IsPointer: 1, IsInitialized: 1},
		})
	// Test Union
	testAssertEqualPath(
		t,
		spec,
		"linux_binprm",
		"file.f_inode.i_dir_seq",
		[]api.ConfigBtfArg{
			{Offset: 64, IsPointer: 1, IsInitialized: 1},
			{Offset: 168, IsPointer: 1, IsInitialized: 1},
			{Offset: 0, IsPointer: 1, IsInitialized: 1},
		})
}
func testAssertPathIsAccessible(t *testing.T, spec *btf.Spec) {
	_, _, err := testFindNextBtf(t, spec, "task_struct", "trc_reader_special.b.need_mb")
	assert.NoError(t, err)

	_, _, err = testFindNextBtf(t, spec, "linux_binprm", "mm.pgd.pgd")
	assert.NoError(t, err)
}

func testAssertErrorOnInvalidPath(t *testing.T, spec *btf.Spec) {
	_, _, err := testFindNextBtf(t, spec, "linux_binprm", "mm.pgd.fail")
	assert.ErrorContains(t, err, "Attribute 'fail' not found in structure ''")
}

func TestFindNextBtf(t *testing.T) {
	spec, err := NewBTF()
	if err != nil {
		assert.Error(t, err)
	}
	testAssertPathIsAccessible(t, spec)
	testAssertErrorOnInvalidPath(t, spec)
	testAssertEqualBtfPath(t, spec)
}
