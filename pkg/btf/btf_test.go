// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows
// +build !windows

package btf

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
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

func fatalOnError(t *testing.T, err error) {
	if err != nil {
		assert.Error(t, err)
		t.Fatal(err.Error())
	}
}

func getBtfStruct(ty btf.Type) (*btf.Struct, error) {
	t, ok := ty.(*btf.Struct)
	if ok {
		return t, nil
	}
	return nil, fmt.Errorf("Invalid type for \"%v\", expected \"*btf.Struct\", got %q", t, reflect.TypeOf(ty).String())
}

func getBtfPointer(ty btf.Type) (*btf.Pointer, error) {
	t, ok := ty.(*btf.Pointer)
	if ok {
		return t, nil
	}
	return nil, fmt.Errorf("Invalid type for \"%v\", expected \"*btf.Pointer\", got %q", t, reflect.TypeOf(ty).String())
}

func findMemberInBtfStruct(structTy *btf.Struct, memberName string) (*btf.Member, error) {
	for _, member := range structTy.Members {
		if member.Name == memberName {
			return &member, nil
		}

		if anonymousStructTy, ok := member.Type.(*btf.Struct); ok && len(member.Name) == 0 {
			for _, m := range anonymousStructTy.Members {
				if m.Name == memberName {
					return &m, nil
				}
			}
		}

		if unionTy, ok := member.Type.(*btf.Union); ok {
			for _, m := range unionTy.Members {
				if m.Name == memberName {
					return &m, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("Member %q not found in struct %v", memberName, structTy)
}

func getBtfPointerAndSetConfig(ty btf.Type, btfConfig *api.ConfigBtfArg) (*btf.Pointer, error) {
	ptr, err := getBtfPointer(ty)
	if err != nil {
		return nil, err
	}
	btfConfig.IsInitialized = uint16(1)
	btfConfig.IsPointer = uint16(1)

	return ptr, nil
}

func getConfigAndNextType(structTy *btf.Struct, memberName string) (*btf.Type, *api.ConfigBtfArg, error) {
	btfConfig := api.ConfigBtfArg{}

	member, err := findMemberInBtfStruct(structTy, memberName)
	if err != nil {
		return nil, nil, err
	}

	btfConfig.Offset = uint32(member.Offset.Bytes())
	btfConfig.IsInitialized = uint16(1)

	ty := ResolveNestedTypes(member.Type)

	ptr, _ := getBtfPointerAndSetConfig(ty, &btfConfig)
	if ptr != nil {
		return &ptr.Target, &btfConfig, err
	}
	if _, ok := ty.(*btf.Int); ok {
		btfConfig.IsPointer = uint16(1)
	}
	return &ty, &btfConfig, err
}

func getConfigAndNextStruct(structTy *btf.Struct, memberName string) (*btf.Struct, *api.ConfigBtfArg, error) {
	btfConfig := api.ConfigBtfArg{}

	member, err := findMemberInBtfStruct(structTy, memberName)
	if err != nil {
		return nil, nil, err
	}

	btfConfig.Offset = uint32(member.Offset.Bytes())
	btfConfig.IsInitialized = uint16(1)

	ty := ResolveNestedTypes(member.Type)

	ptr, _ := getBtfPointerAndSetConfig(ty, &btfConfig)
	if ptr != nil {
		t, err := getBtfStruct(ptr.Target)
		return t, &btfConfig, err
	}
	t, err := getBtfStruct(ty)
	return t, &btfConfig, err
}

func addPaddingOnNestedPtr(ty btf.Type, path []string) []string {
	if t, ok := ty.(*btf.Pointer); ok {
		updatedPath := append([]string{""}, path...)
		return addPaddingOnNestedPtr(t.Target, updatedPath)
	}
	return path
}

func resolveNestedPtr(rootType btf.Type, btfArgs *[api.MaxBtfArgDepth]api.ConfigBtfArg, i int) (btf.Type, int) {
	if ptr, ok := rootType.(*btf.Pointer); ok {
		btfArgs[i] = api.ConfigBtfArg{}
		ty, err := getBtfPointerAndSetConfig(ptr, &btfArgs[i])
		if err != nil {
			return ty.Target, i
		}
		return resolveNestedPtr(ty.Target, btfArgs, i+1)
	}
	return rootType, i
}

func manuallyResolveBtfPath(t *testing.T, rootType btf.Type, p []string) [api.MaxBtfArgDepth]api.ConfigBtfArg {
	var btfArgs [api.MaxBtfArgDepth]api.ConfigBtfArg
	var i int

	rootType, i = resolveNestedPtr(rootType, &btfArgs, 0)

	currentStruct, err := getBtfStruct(rootType)
	fatalOnError(t, err)

	for ; i < len(p); i++ {
		step := p[i]
		if len(step) == 0 {
			btfArgs[i] = api.ConfigBtfArg{}
			ptr, err := getBtfPointerAndSetConfig(ResolveNestedTypes(rootType), &btfArgs[i])
			fatalOnError(t, err)
			currentStruct, err = getBtfStruct(ptr.Target)
			fatalOnError(t, err)
		} else if i < len(p)-1 {
			ty, nextConfig, err := getConfigAndNextStruct(currentStruct, step)
			fatalOnError(t, err)
			currentStruct = ty
			btfArgs[i] = *nextConfig
		} else {
			_, nextConfig, err := getConfigAndNextType(currentStruct, step)
			fatalOnError(t, err)
			btfArgs[i] = *nextConfig
			return btfArgs
		}
	}
	return btfArgs
}

func buildPathFromString(t *testing.T, rootType btf.Type, pathStr string) []string {
	pathBase := strings.Split(pathStr, ".")
	path := addPaddingOnNestedPtr(rootType, pathBase)
	if len(path) > api.MaxBtfArgDepth {
		assert.Fail(t, "Unable to resolve %q. The maximum depth allowed is %d", pathStr, api.MaxBtfArgDepth)
	}
	return path
}

func buildResolveBtfConfig(t *testing.T, rootType btf.Type, pathStr string) [api.MaxBtfArgDepth]api.ConfigBtfArg {
	var btfArgs [api.MaxBtfArgDepth]api.ConfigBtfArg

	path := buildPathFromString(t, rootType, pathStr)
	_, err := ResolveBtfPath(&btfArgs, rootType, path, 0)
	fatalOnError(t, err)

	return btfArgs
}

func buildExpectedBtfConfig(t *testing.T, rootType btf.Type, pathStr string) [api.MaxBtfArgDepth]api.ConfigBtfArg {
	path := buildPathFromString(t, rootType, pathStr)
	return manuallyResolveBtfPath(t, rootType, path)
}

func testPathIsAccessible(rootType btf.Type, strPath string) (*[api.MaxBtfArgDepth]api.ConfigBtfArg, *btf.Type, error) {
	var btfArgs [api.MaxBtfArgDepth]api.ConfigBtfArg
	path := strings.Split(strPath, ".")

	lastBtfType, err := ResolveBtfPath(&btfArgs, ResolveNestedTypes(rootType), path, 0)
	if err != nil {
		return nil, nil, err
	}

	return &btfArgs, lastBtfType, nil
}

func testAssertEqualPath(t *testing.T) {
	hook := "security_bprm_check"
	argIndex := 0 // struct linux_binprm *bprm
	funcParamTy, err := FindBtfFuncParamFromHook(hook, argIndex)
	fatalOnError(t, err)

	bprmTy := funcParamTy.Type
	if ty, ok := bprmTy.(*btf.Pointer); ok {
		bprmTy = ty.Target
	}

	// Test default behaviour
	path := "file.f_path.dentry.d_name.name"
	assert.Equal(t,
		buildExpectedBtfConfig(t, bprmTy, path),
		buildResolveBtfConfig(t, bprmTy, path),
	)

	// Test anonymous struct
	path = "mm.arg_start"
	assert.Equal(t,
		buildExpectedBtfConfig(t, bprmTy, path),
		buildResolveBtfConfig(t, bprmTy, path),
	)

	// Test Union
	path = "file.f_inode.i_dir_seq"
	assert.Equal(t,
		buildExpectedBtfConfig(t, bprmTy, path),
		buildResolveBtfConfig(t, bprmTy, path),
	)

	// Test if param is double ptr
	hook = "security_inode_copy_up"
	argIndex = 1 // struct cred **new
	funcParamTy, err = FindBtfFuncParamFromHook(hook, argIndex)
	fatalOnError(t, err)

	newTy := funcParamTy.Type
	if ty, ok := newTy.(*btf.Pointer); ok {
		newTy = ty.Target
	}
	path = "uid.val"
	assert.Equal(t,
		buildExpectedBtfConfig(t, newTy, path),
		buildResolveBtfConfig(t, newTy, path),
	)
}

func testAssertPathIsAccessible(t *testing.T) {
	hook := "wake_up_new_task"
	argIndex := 0 //struct task_struct *p
	funcParamTy, err := FindBtfFuncParamFromHook(hook, argIndex)
	fatalOnError(t, err)

	taskStructTy := funcParamTy.Type
	if ty, ok := taskStructTy.(*btf.Pointer); ok {
		taskStructTy = ty.Target
	}

	_, _, err = testPathIsAccessible(taskStructTy, "sched_task_group.css.id")
	assert.NoError(t, err)

	hook = "security_bprm_check"
	argIndex = 0 // struct linux_binprm *bprm
	funcParamTy, err = FindBtfFuncParamFromHook(hook, argIndex)
	fatalOnError(t, err)

	bprmTy := funcParamTy.Type
	if ty, ok := bprmTy.(*btf.Pointer); ok {
		bprmTy = ty.Target
	}

	_, _, err = testPathIsAccessible(bprmTy, "mm.pgd.pgd")
	assert.NoError(t, err)
}

func testAssertErrorOnInvalidPath(t *testing.T) {
	hook := "security_bprm_check"
	argIndex := 0 // struct linux_binprm *bprm
	funcParamTy, err := FindBtfFuncParamFromHook(hook, argIndex)
	fatalOnError(t, err)

	rootType := funcParamTy.Type
	if rootTy, ok := rootType.(*btf.Pointer); ok {
		rootType = rootTy.Target
	}

	// Assert an error is raised when attribute does not exists
	_, _, err = testPathIsAccessible(rootType, "fail")
	assert.ErrorContains(t, err, "Attribute \"fail\" not found in structure")

	_, _, err = testPathIsAccessible(rootType, "mm.fail")
	assert.ErrorContains(t, err, "Attribute \"fail\" not found in structure")

	_, _, err = testPathIsAccessible(rootType, "mm.pgd.fail")
	assert.ErrorContains(t, err, "Attribute \"fail\" not found in structure")

	hook = "do_sys_open"
	argIndex = 0 // int dfd
	funcParamTy, err = FindBtfFuncParamFromHook(hook, argIndex)
	fatalOnError(t, err)

	rootType = funcParamTy.Type

	// Assert an error is raised when attribute has invalid type
	_, _, err = testPathIsAccessible(rootType, "fail")
	assert.ErrorContains(t, err, fmt.Sprintf("Unexpected type : \"fail\" has type %q", rootType.TypeName()))
}

func TestResolveBtfPath(t *testing.T) {
	t.Run("PathIsAccessible", testAssertPathIsAccessible)
	t.Run("AssertErrorOnInvalidPath", testAssertErrorOnInvalidPath)
	t.Run("AssertEqualPath", testAssertEqualPath)
}
