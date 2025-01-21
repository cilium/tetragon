// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

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

func genericTestFindBtfFuncParamFromHook(t *testing.T, hook string, argIndex int, expectedName string) error {
	param, err := FindBtfFuncParamFromHook(hook, argIndex)
	if err != nil {
		return err
	}

	assert.NotNil(t, param)
	assert.Equal(t, expectedName, param.Name)

	return nil
}

func TestFindBtfFuncParamFromHook(t *testing.T) {
	// Assert no errors on Kprobe
	hook := "wake_up_new_task"
	argIndex := 0
	expectedName := "p"
	err := genericTestFindBtfFuncParamFromHook(t, hook, argIndex, expectedName)
	assert.NoError(t, err)

	// Assert error raises with invalid hook
	hook = "fake_hook"
	argIndex = 0
	expectedName = "p"
	err = genericTestFindBtfFuncParamFromHook(t, hook, argIndex, expectedName)
	assert.ErrorContains(t, err, fmt.Sprintf("failed to find BTF type for hook %q", hook))

	// Assert error raises when hook is a valid BTF type but not btf.Func
	hook = "linux_binprm"
	argIndex = 0
	expectedName = "p"
	err = genericTestFindBtfFuncParamFromHook(t, hook, argIndex, expectedName)
	assert.ErrorContains(t, err, fmt.Sprintf("failed to find BTF type for hook %q", hook))

	// Assert error raises when argIndex is out of scope
	hook = "wake_up_new_task"
	argIndex = 10
	expectedName = "p"
	err = genericTestFindBtfFuncParamFromHook(t, hook, argIndex, expectedName)
	assert.ErrorContains(t, err, fmt.Sprintf("index %d is out of range", argIndex))
}
