// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	bc "github.com/cilium/tetragon/pkg/matchers/bytesmatcher"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/pkg/sensors/base"
	_ "github.com/cilium/tetragon/pkg/sensors/exec"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	testConfigFile = "/tmp/tetragon.gotest.yaml"
)

var (
	allFiles = [4]string{
		"/etc/passwd",
		"/etc/group",
		"/etc/hostname",
		"/etc/shadow",
	}
)

func TestKprobeObjectLoad(t *testing.T) {
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 2
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        values:
        - 25587
      matchArgs:
      - index: 0
        operator: Equal
        values:
        - "1"
`
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	writeConfigHook := []byte(writeReadHook)
	err := os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	_, err = observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	initialSensor := base.GetInitialSensor()
	initialSensor.Load(bpf.MapPrefixPath(), bpf.MapPrefixPath(), "")
}

// NB: This is similar to TestKprobeObjectWriteRead, but it's a bit easier to
// debug because we can write things on stdout which will not generate events.
func TestKprobeLseek(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	t.Logf("tester pid=%s\n", pidStr)

	lseekConfigHook_ := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_lseek"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr

	lseekConfigHook := []byte(lseekConfigHook_)
	err := os.WriteFile(testConfigFile, lseekConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)
}

func getTestKprobeObjectWRChecker(t *testing.T) ec.MultiEventChecker {
	myNs := ec.NewNamespacesChecker().FromNamespaces(namespace.GetCurrentNamespace())
	myCaps := ec.NewCapabilitiesChecker().FromCapabilities(caps.GetCurrentCapabilities())

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_write"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("hello world"))),
				ec.NewKprobeArgumentChecker().WithSizeArg(11),
			)).
		WithProcess(ec.NewProcessChecker().
			WithCap(myCaps).
			WithNs(myNs))
	return ec.NewUnorderedEventChecker(kpChecker)
}

func runKprobeObjectWriteRead(t *testing.T, writeReadHook string) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	writeConfigHook := []byte(writeReadHook)
	err := os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	checker := getTestKprobeObjectWRChecker(t)

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	_, err = syscall.Write(1, []byte("hello world"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeObjectWriteReadHostNs(t *testing.T) {
	// if we run inside a container it will not match the host namespace
	nsOp := "NotIn"
	if _, err := os.Stat("/.dockerenv"); errors.Is(err, os.ErrNotExist) {
		nsOp = "In"
	}
	myPid := observer.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchNamespaces:
      - namespace: Mnt
        operator: ` + nsOp + `
        values:
        - "host_ns"
      - namespace: Pid
        operator: ` + nsOp + `
        values:
        - "host_ns"
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func TestKprobeObjectWriteRead(t *testing.T) {
	myPid := observer.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	mntNsStr := strconv.FormatUint(uint64(namespace.GetPidNsInode(myPid, "mnt")), 10)
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchNamespaces:
      - namespace: Mnt
        operator: In
        values:
        - ` + mntNsStr + `
      matchCapabilities:
      - type: Permitted
        operator: In
        values:
        - "CAP_SETPCAP"
        - "CAP_SYS_ADMIN"
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func TestKprobeObjectWriteCapsNotIn(t *testing.T) {
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchCapabilities:
      - type: Inheritable # these are 0x00 for root
        operator: NotIn
        values:
        - "CAP_SYS_ADMIN"
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func TestKprobeObjectWriteReadNsOnly(t *testing.T) {
	myPid := observer.GetMyPid()
	mntNsStr := strconv.FormatUint(uint64(namespace.GetPidNsInode(myPid, "mnt")), 10)
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchNamespaces:
      - namespace: Mnt
        operator: In
        values:
        - ` + mntNsStr + `
      matchCapabilities:
      - type: Permitted
        operator: In
        values:
        - "CAP_SETPCAP"
        - "CAP_SYS_ADMIN"
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func TestKprobeObjectWriteReadPidOnly(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func createTestFile(t *testing.T) (int, int, string) {
	// Create file with hello world to read
	fd, errno := syscall.Open("/tmp/testfile", syscall.O_CREAT|syscall.O_TRUNC|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd) })
	t.Cleanup(func() { os.Remove("/tmp/testfile") })
	fd2, errno := syscall.Open("/tmp/testfile", syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		t.Logf("File open fro read failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd2) })
	return fd, fd2, fmt.Sprint(fd2)
}

func runKprobeObjectRead(t *testing.T, readHook string, checker ec.MultiEventChecker, fd, fd2 int) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	readConfigHook := []byte(readHook)
	err := os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	hello := []byte("hello world")
	n, errno := syscall.Write(fd, hello)
	if n < 0 {
		t.Logf("syscall.Write failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Fsync(fd)
	var readBytes = make([]byte, 100)
	i, errno := syscall.Read(fd2, readBytes)
	if i < 0 {
		t.Logf("syscall.Read failed: %s\n", errno)
		t.Fatal()
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeObjectRead(t *testing.T) {
	fd, fd2, fdString := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      returnCopy: true
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fdString

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_read"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fd2)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("hello world"))),
				ec.NewKprobeArgumentChecker().WithSizeArg(100),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeObjectRead(t, readHook, checker, fd, fd2)
}

func TestKprobeObjectReadReturn(t *testing.T) {
	fd, fd2, fdString := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
    return: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      returnCopy: true
    - index: 2
      type: "size_t"
    returnArg:
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fdString

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_read"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fd2)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("hello world"))),
				ec.NewKprobeArgumentChecker().WithSizeArg(100),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithSizeArg(11))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeObjectRead(t, readHook, checker, fd, fd2)
}

// sys_openat trace
func getOpenatChecker(t *testing.T, dir string) ec.MultiEventChecker {
	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(-100),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(filepath.Join(dir, "testfile"))),
				ec.NewKprobeArgumentChecker(),
			))

	return ec.NewUnorderedEventChecker(kpChecker)
}

// matches any kprobe event, used to test filters
func getAnyChecker() ec.MultiEventChecker {
	return ec.NewUnorderedEventChecker(ec.NewProcessKprobeChecker("anyKprobe"))
}

func testKprobeObjectFiltered(t *testing.T,
	readHook string,
	checker ec.MultiEventChecker,
	useMount bool,
	mntPath string,
	expectFailure bool,
	mode int,
	perm uint32) {

	if useMount == true {
		if err := syscall.Mount("tmpfs", mntPath, "tmpfs", 0, ""); err != nil {
			t.Logf("Mount failed: %s\n", err)
			t.Skip()
		}
		t.Cleanup(func() {
			if err := syscall.Unmount(mntPath, 0); err != nil {
				t.Logf("Unmount failed: %s\n", err)
			}
		})
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	filePath := mntPath + "/testfile"

	// Create file to open later
	fd, errno := syscall.Open(filePath, syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Close(fd)

	readConfigHook := []byte(readHook)
	err := os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	fd2, errno := syscall.Open(filePath, mode, perm)
	if fd2 < 0 {
		t.Logf("File open from read failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd2) })
	data := "hello world"
	n, err := syscall.Write(fd2, []byte(data))
	assert.Equal(t, len(data), n)
	assert.NoError(t, err)
	err = jsonchecker.JsonTestCheckExpect(t, checker, expectFailure)
	assert.NoError(t, err)
}

func testKprobeObjectOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: false
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Equal"
          values:
          - "` + path + `/testfile\0"
  `
}

func TestKprobeObjectOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectMultiValueOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: false
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Equal"
          values:
          - "` + path + `/foobar\0"
          - "` + path + `/testfile\0"
  `
}

func TestKprobeObjectMultiValueOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectMultiValueOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + dir + `/foofile\0"
`
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, dir, true, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectMultiValueFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + dir + `/foo\0"
        - "` + dir + `/bar\0"
`
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, dir, true, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterPrefixOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: false
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Prefix"
          values:
          - "` + path + `/testf"
  `
}

func TestKprobeObjectFilterPrefixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterPrefixExactOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: false
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Prefix"
          values:
          - "` + path + `/testfile"
  `
}

func TestKprobeObjectFilterPrefixExactOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixExactOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterPrefixSubdirOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: false
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Prefix"
          values:
          - "` + path + `/"
  `
}

func TestKprobeObjectFilterPrefixSubdirOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixSubdirOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixMissOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "/foo/"
`
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, dir, true, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectPostfixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Postfix"
        values:
        - "testfile\0"
`
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterModeOpenHook(pidStr string, mode int, valueFmt string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: false
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      - index: 3
        type: "int"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 2
          operator: "Mask"
          values:
          - ` + fmt.Sprintf(valueFmt, mode) + `
  `
}

func testKprobeObjectFilterModeOpenMatch(t *testing.T, valueFmt string, modeCreate, modeCheck int) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	checker := func(dir string) *eventchecker.UnorderedEventChecker {
		return ec.NewUnorderedEventChecker(
			ec.NewProcessKprobeChecker("").
				WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
				WithArgs(ec.NewKprobeArgumentListMatcher().
					WithOperator(lc.Ordered).
					WithValues(
						ec.NewKprobeArgumentChecker().WithIntArg(-100),
						ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(filepath.Join(dir, "testfile"))),
						ec.NewKprobeArgumentChecker(),
						ec.NewKprobeArgumentChecker(),
					)))
	}

	dir := t.TempDir()
	openHook := testKprobeObjectFilterModeOpenHook(pidStr, modeCheck, valueFmt)
	testKprobeObjectFiltered(t, openHook, checker(dir), false, dir, false, modeCreate, 0x770)
}

func TestKprobeObjectFilterModeOpenMatchDec(t *testing.T) {
	testKprobeObjectFilterModeOpenMatch(t, "%d", syscall.O_RDWR|syscall.O_TRUNC|syscall.O_CLOEXEC, syscall.O_TRUNC)
}

func TestKprobeObjectFilterModeOpenMatchHex(t *testing.T) {
	testKprobeObjectFilterModeOpenMatch(t, "0x%x", syscall.O_RDWR|syscall.O_TRUNC|syscall.O_CLOEXEC, syscall.O_RDWR)
}

func TestKprobeObjectFilterModeOpenMatchOct(t *testing.T) {
	testKprobeObjectFilterModeOpenMatch(t, "0%d", syscall.O_RDWR|syscall.O_TRUNC|syscall.O_CLOEXEC, syscall.O_CLOEXEC)
}

func TestKprobeObjectFilterModeOpenFail(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	openHook := testKprobeObjectFilterModeOpenHook(pidStr, syscall.O_TRUNC, "%d")
	testKprobeObjectFiltered(t, openHook, getAnyChecker(), false, dir, true, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterReturnValueGTHook(pidStr, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: true
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      returnArg:
        type: int
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Equal"
          values:
          - "` + path + `\0"
        matchReturnArgs:
        - index: 0
          operator: "GT"
          values:
          - 0
  `
}

func testKprobeObjectFilterReturnValueLTHook(pidStr, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "sys_openat"
      return: true
      syscall: true
      args:
      - index: 0
        type: int
      - index: 1
        type: "string"
      - index: 2
        type: "int"
      returnArg:
        type: int
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Equal"
          values:
          - "` + path + `\0"
        matchReturnArgs:
        - index: 0
          operator: "LT"
          values:
          - 0
  `
}

func testKprobeObjectFilteredReturnValue(t *testing.T,
	hook string,
	checker ec.MultiEventChecker,
	path string,
	expectFailure bool) {

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	readConfigHook := []byte(hook)
	err := os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	fd2, _ := syscall.Open(path, syscall.O_RDWR, 0x770)
	t.Cleanup(func() { syscall.Close(fd2) })
	err = jsonchecker.JsonTestCheckExpect(t, checker, expectFailure)
	assert.NoError(t, err)
}

func TestKprobeObjectFilterReturnValueGTOk(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	path := dir + "/testfile"
	openHook := testKprobeObjectFilterReturnValueGTHook(pidStr, path)

	checker := func(dir string) *eventchecker.UnorderedEventChecker {
		return ec.NewUnorderedEventChecker(
			ec.NewProcessKprobeChecker("").
				WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
				WithArgs(ec.NewKprobeArgumentListMatcher().
					WithOperator(lc.Ordered).
					WithValues(
						ec.NewKprobeArgumentChecker().WithIntArg(-100),
						ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(path)),
						ec.NewKprobeArgumentChecker(),
					)))
	}

	// Create file to open later
	fd, errno := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Close(fd)
	defer func() { syscall.Unlink(path) }()

	// testfile exists
	// we look for sys_openat(-100, "...testfile", ..) > 0
	testKprobeObjectFilteredReturnValue(t, openHook, checker(path), path, false /* OK */)
}

func TestKprobeObjectFilterReturnValueGTFail(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	path := dir + "/testfile"
	openHook := testKprobeObjectFilterReturnValueGTHook(pidStr, path)

	// testfile DOES NOT exist
	// we look for sys_openat(-100, "...testfile", ..) > 0
	testKprobeObjectFilteredReturnValue(t, openHook, getAnyChecker(), path, true /* FAIL */)
}

func TestKprobeObjectFilterReturnValueLTOk(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	path := dir + "/testfile"
	openHook := testKprobeObjectFilterReturnValueLTHook(pidStr, path)

	checker := func(dir string) *eventchecker.UnorderedEventChecker {
		return ec.NewUnorderedEventChecker(
			ec.NewProcessKprobeChecker("").
				WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
				WithArgs(ec.NewKprobeArgumentListMatcher().
					WithOperator(lc.Ordered).
					WithValues(
						ec.NewKprobeArgumentChecker().WithIntArg(-100),
						ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(path)),
						ec.NewKprobeArgumentChecker(),
					)))
	}

	// testfile DOES NOT exist
	// we look for sys_openat(-100, "...testfile", ..) < 0
	testKprobeObjectFilteredReturnValue(t, openHook, checker(path), path, false /* OK */)
}

func TestKprobeObjectFilterReturnValueLTFail(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	path := dir + "/testfile"
	openHook := testKprobeObjectFilterReturnValueLTHook(pidStr, path)

	// Create file to open later
	fd, errno := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Close(fd)
	defer func() { syscall.Unlink(path) }()

	// testfile exists
	// we look for sys_openat(-100, "...testfile", ..) < 0
	testKprobeObjectFilteredReturnValue(t, openHook, getAnyChecker(), path, true /* FAIL */)
}

func helloIovecWorldWritev() (err error) {
	var arrayOfBytes = make([][]byte, 3)

	h := []byte("hello")
	i := []byte(" iovec ")
	w := []byte("world")

	arrayOfBytes[0] = h
	arrayOfBytes[1] = i
	arrayOfBytes[2] = w
	_, err = unix.Writev(1, arrayOfBytes)
	return err
}

func TestKprobeObjectWriteVRead(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-writev"
spec:
  kprobes:
  - call: "sys_writev"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_iovec"
      sizeArgIndex: 3
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: Equal
        values:
        - 1
`
	writeConfigHook := []byte(writeReadHook)
	err := os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(tus.Conf().SelfBinary))).
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_writev"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("hello iovec world"))),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = helloIovecWorldWritev()
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func getFilpOpenChecker(dir string) ec.MultiEventChecker {
	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("do_filp_open")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(-100),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(filepath.Join(dir, "testfile"))),
			))

	return ec.NewUnorderedEventChecker(kpChecker)
}

func TestKprobeObjectFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "do_filp_open"
    return: false
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "filename"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
     `
	testKprobeObjectFiltered(t, readHook, getFilpOpenChecker(dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectReturnFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "do_filp_open"
    return: true
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "filename"
    returnArg:
      type: file
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
     `
	testKprobeObjectFiltered(t, readHook, getFilpOpenChecker(dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFileWriteHook(pidStr string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "fd_install"
      return: false
      syscall: false
      args:
      - index: 0
        type: int
      - index: 1
        type: "file"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchActions:
        - action: followfd
          argFd: 0
          argName: 1
    - call: "sys_write"
      syscall: true
      args:
      - index: 0
        type: "fd"
      - index: 1
        type: "char_buf"
        sizeArgIndex: 3
      - index: 2
        type: "size_t"
      selectors:
      - matchPIDs:
        - operator: In
          values:
          - ` + pidStr + `
  `
}

func testKprobeObjectFileWriteFilteredHook(pidStr string, dir string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys-read"
  spec:
    kprobes:
    - call: "fd_install"
      return: false
      syscall: false
      args:
      - index: 0
        type: int
      - index: 1
        type: "file"
      selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Postfix"
          values:
          - "` + dir + `/testfile"
        matchActions:
        - action: followfd
          argFd: 0
          argName: 1
    - call: "sys_write"
      syscall: true
      args:
      - index: 0
        type: "fd"
      - index: 1
        type: "char_buf"
        sizeArgIndex: 3
      - index: 2
        type: "size_t"
      selectors:
      - matchPIDs:
        - operator: In
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 0
          operator: "Postfix"
          values:
          - "` + dir + `/testfile"
  `
}

func getWriteChecker(t *testing.T, path, flags string) ec.MultiEventChecker {
	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_write"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().
					WithPath(sm.Suffix(path)).
					WithFlags(sm.Full(flags)),
				),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("hello world"))),
				ec.NewKprobeArgumentChecker().WithSizeArg(11),
			)).
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(tus.Conf().SelfBinary)))

	return ec.NewUnorderedEventChecker(kpChecker)
}

func TestKprobeObjectFileWrite(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(t, filepath.Join(dir, "testfile"), ""), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFileWriteFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(t, filepath.Join(dir, "testfile"), ""), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFileWriteMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(t, filepath.Join(dir, "testfile"), ""), true, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFileWriteMountFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(t, filepath.Join(dir, "testfile"), ""), true, dir, false, syscall.O_RDWR, 0x770)
}

func corePathTest(t *testing.T, filePath string, readHook string, writeChecker ec.MultiEventChecker) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	// Create file to open later
	fd, errno := syscall.Open(filePath, syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Close(fd)

	readConfigHook := []byte(readHook)
	err := os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fd2, errno := syscall.Open(filePath, syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		t.Logf("File open from read failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd2) })
	data := "hello world"
	n, err := syscall.Write(fd2, []byte(data))
	assert.Equal(t, len(data), n)
	assert.NoError(t, err)
	err = jsonchecker.JsonTestCheck(t, writeChecker)
	assert.NoError(t, err)
}

func testMultipleMountsFiltered(t *testing.T, readHook string) {
	var pathStack []string

	// let's create /tmp2/tmp3/tmp4/tmp5 where each dir is a mount point
	path := "/"
	for i := 2; i < 6; i++ {
		path = filepath.Join(path, fmt.Sprintf("tmp%d", i))
		pathStack = append(pathStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
		if err := syscall.Mount("tmpfs", path, "tmpfs", 0, ""); err != nil {
			t.Logf("Mount failed: %s\n", err)
			t.Skip()
		}
	}
	t.Cleanup(func() {
		// let's clear all
		for len(pathStack) > 0 {
			n := len(pathStack) - 1
			path := pathStack[n]
			if err := syscall.Unmount(path, 0); err != nil {
				t.Logf("Unmount failed: %s\n", err)
			}
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			pathStack = pathStack[:n]
		}
	})

	filePath := path + "/testfile"

	writeChecker := getWriteChecker(t, "/tmp2/tmp3/tmp4/tmp5/testfile", "")

	corePathTest(t, filePath, readHook, writeChecker)
}

func testMultiplePathComponentsFiltered(t *testing.T, readHook string) {
	var pathStack []string
	path := "/tmp"

	// let's create /tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16 where each dir is a directory
	for i := 0; i <= 16; i++ {
		path = filepath.Join(path, fmt.Sprintf("%d", i))
		pathStack = append(pathStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
	}
	t.Cleanup(func() {
		if err := os.Remove(path + "/testfile"); err != nil {
			t.Logf("Remove testfile failed: %s\n", err)
		}
		// let's clear all
		for len(pathStack) > 0 {
			n := len(pathStack) - 1
			path := pathStack[n]
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			pathStack = pathStack[:n]
		}
	})

	filePath := path + "/testfile"
	writeChecker := getWriteChecker(t, "/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = getWriteChecker(t, "/tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
	}

	corePathTest(t, filePath, readHook, writeChecker)
}

func testMultipleMountPathFiltered(t *testing.T, readHook string) {
	var pathStack []string
	var dirStack []string
	path := "/"

	// let's create /tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16
	// tmp* are mount points
	// the rest are directories
	for i := 2; i < 6; i++ {
		path = filepath.Join(path, fmt.Sprintf("tmp%d", i))
		pathStack = append(pathStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
		if err := syscall.Mount("tmpfs", path, "tmpfs", 0, ""); err != nil {
			t.Logf("Mount failed: %s\n", err)
			t.Skip()
		}
	}
	for i := 0; i <= 16; i++ {
		path = filepath.Join(path, fmt.Sprintf("%d", i))
		dirStack = append(dirStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
	}
	t.Cleanup(func() {
		if err := os.Remove(path + "/testfile"); err != nil {
			t.Logf("Remove testfile failed: %s\n", err)
		}

		// let's clear all
		for len(dirStack) > 0 {
			n := len(dirStack) - 1
			path := dirStack[n]
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			dirStack = dirStack[:n]
		}
		for len(pathStack) > 0 {
			n := len(pathStack) - 1
			path := pathStack[n]
			if err := syscall.Unmount(path, 0); err != nil {
				t.Logf("Unmount failed: %s\n", err)
			}
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			pathStack = pathStack[:n]
		}
	})

	filePath := path + "/testfile"
	writeChecker := getWriteChecker(t, "/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = getWriteChecker(t, "/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
	}

	corePathTest(t, filePath, readHook, writeChecker)
}

func TestMultipleMountsFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5")
	testMultipleMountsFiltered(t, readHook)
}

func TestMultiplePathComponents(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testMultiplePathComponentsFiltered(t, readHook)
}

func TestMultipleMountPath(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testMultipleMountPathFiltered(t, readHook)
}

func TestMultipleMountPathFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16")
	testMultipleMountPathFiltered(t, readHook)
}

func TestKprobeArgValues(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-linkat-args"
spec:
  kprobes:
  - call: "sys_linkat"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    - index: 3
      type: "string"
    - index: 4
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
     `

	oldFile := "file-old"
	newFile := "file-new"
	var oldFd int32 = -123
	var newFd int32 = -321
	var flags int32 = 12345

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_linkat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(oldFd),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(oldFile)),
				ec.NewKprobeArgumentChecker().WithIntArg(newFd),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(newFile)),
				ec.NewKprobeArgumentChecker().WithIntArg(flags),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	readConfigHook := []byte(readHook)
	err := os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	// linkat syscall is not exported for some reason
	// so calling linkat via Syscall6 interface

	oldBytes, err := syscall.BytePtrFromString(oldFile)
	if err != nil {
		t.Fatalf("BytePtrFromString error: %s", err)
	}

	newBytes, err := syscall.BytePtrFromString(newFile)
	if err != nil {
		t.Fatalf("BytePtrFromString error: %s", err)
	}

	// we don't need to check for error, it will fail, so there's
	// no need to cleanup.. we care only about kprobe catching
	// and storing arguments

	syscall.Syscall6(syscall.SYS_LINKAT,
		uintptr(oldFd), uintptr(unsafe.Pointer(oldBytes)),
		uintptr(newFd), uintptr(unsafe.Pointer(newBytes)),
		uintptr(flags), 0)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// override

func runKprobeOverride(t *testing.T, hook string, checker ec.MultiEventChecker,
	testFile string, testErr error, nopost bool) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	if !bpf.HasOverrideHelper() {
		t.Skip("skipping override test, bpf_override_return helper not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	configHook := []byte(hook)
	err := os.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fd, err := syscall.Open(testFile, syscall.O_RDWR, 0x777)
	if fd >= 0 {
		t.Logf("syscall.Open succeeded\n")
		syscall.Close(fd)
		t.Fatal()
	}

	if !errors.Is(err, testErr) {
		t.Logf("syscall.Open succeeded\n")
		syscall.Close(fd)
		t.Fatal()
	}

	err = jsonchecker.JsonTestCheck(t, checker)

	if nopost {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

func TestKprobeOverride(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-openat-override"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    returnArg:
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + file.Name() + `\0"
      matchActions:
      - action: Override
        argError: -2
`

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-2)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeOverride(t, openAtHook, checker, file.Name(), syscall.ENOENT, false)
}

func TestKprobeOverrideNopostAction(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-openat-override"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    returnArg:
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + file.Name() + `\0"
      matchActions:
      - action: Override
        argError: -2
      - action: NoPost
`

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-2)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeOverride(t, openAtHook, checker, file.Name(), syscall.ENOENT, true)
}

func TestKprobeOverrideNonSyscall(t *testing.T) {
	closeFdHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "close-fd-override"
spec:
  kprobes:
  - call: "close_fd"
    syscall: false
    args:
    - index: 0
      type: "int"
    selectors:
    - matchActions:
      - action: Override
        argError: -2
`

	configHook := []byte(closeFdHook)
	err := os.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	_, err = observer.GetDefaultObserverWithFileNoTest(t, context.Background(), testConfigFile, tus.Conf().TetragonLib, true, observer.WithMyPid())
	if err == nil {
		t.Fatalf("GetDefaultObserverWithFileNoTest ok, should fail\n")
	}
	assert.Error(t, err)
}

func runKprobeOverrideSignal(t *testing.T, hook string, checker ec.MultiEventChecker,
	testFile string, testErr error, nopost bool, expectedSig syscall.Signal) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	if !bpf.HasOverrideHelper() {
		t.Skip("skipping override test, bpf_override_return helper not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	configHook := []byte(hook)
	err := os.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, expectedSig)

	fd, err := syscall.Open(testFile, syscall.O_RDWR, 0x777)
	if fd >= 0 {
		t.Logf("syscall.Open succeeded\n")
		syscall.Close(fd)
		t.Fatal()
	}

	if !errors.Is(err, testErr) {
		t.Logf("syscall.Open succeeded\n")
		syscall.Close(fd)
		t.Fatal()
	}

	sig := <-sigs

	if sig != expectedSig {
		t.Fatalf("got wrong signal number %d, expocted %d", sig, expectedSig)
	}

	err = jsonchecker.JsonTestCheck(t, checker)

	if nopost {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

func TestKprobeOverrideSignal(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip()
	}
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-openat-override-signal"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    returnArg:
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + file.Name() + `\0"
      matchActions:
      - action: Override
        argError: -2
      - action: Signal
        argSig: 10
`

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-2)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGNAL)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeOverrideSignal(t, openAtHook, checker, file.Name(), syscall.ENOENT, false, syscall.SIGUSR1)
}

func TestKprobeSignalOverride(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip()
	}
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-openat-signal-override"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    returnArg:
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + file.Name() + `\0"
      matchActions:
      - action: Signal
        argSig: 12
      - action: Override
        argError: -2
`

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-2)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeOverrideSignal(t, openAtHook, checker, file.Name(), syscall.ENOENT, false, syscall.SIGUSR2)
}

func TestKprobeSignalOverrideNopost(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip()
	}
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-openat-signal-override"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    returnArg:
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + file.Name() + `\0"
      matchActions:
      - action: Signal
        argSig: 10
      - action: Override
        argError: -2
      - action: NoPost
`

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-2)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeOverrideSignal(t, openAtHook, checker, file.Name(), syscall.ENOENT, true, syscall.SIGUSR1)
}

func runKprobe_char_iovec(t *testing.T, configHook string,
	checker *ec.UnorderedEventChecker, fdw, fdr int, buffer []byte) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testConfigHook := []byte(configHook)
	err := os.WriteFile(testConfigFile, testConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	b := base.GetInitialSensor()
	obs, err := observer.GetDefaultObserverWithWatchers(t, ctx, b, observer.WithConfig(testConfigFile), observer.WithLib(tus.Conf().TetragonLib), observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithWatchers error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	// use writev file with single buffer
	// and readv the same file with 8 separate buffers

	var iovw = make([][]byte, 1)
	var iovr = make([][]byte, 8)

	iovw[0] = buffer
	_, err = unix.Writev(fdw, iovw)
	assert.NoError(t, err)

	syscall.Fsync(fdw)

	iovr[0] = make([]byte, 1000)
	iovr[1] = make([]byte, 1100)
	iovr[2] = make([]byte, 1200)
	iovr[3] = make([]byte, 1300)
	iovr[4] = make([]byte, 1400)
	iovr[5] = make([]byte, 1500)
	iovr[6] = make([]byte, 1600)
	iovr[7] = make([]byte, 1700)

	_, err = unix.Readv(fdr, iovr)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobe_char_iovec(t *testing.T) {
	fdw, fdr, _ := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write-writev"
spec:
  kprobes:
  - call: "sys_writev"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_iovec"
      sizeArgIndex: 3
    - index: 2
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fmt.Sprint(fdw)

	size := 4094
	buffer := make([]byte, size)

	for i := 0; i < size; i++ {
		buffer[i] = 'A' + byte(i%26)
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_writev"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdw)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full(buffer)),
				ec.NewKprobeArgumentChecker().WithIntArg(1),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobe_char_iovec(t, configHook, checker, fdw, fdr, buffer)
}

func TestKprobe_char_iovec_overflow(t *testing.T) {
	fdw, fdr, _ := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write-writev"
spec:
  kprobes:
  - call: "sys_writev"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_iovec"
      sizeArgIndex: 3
    - index: 2
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fmt.Sprint(fdw)

	size := 5000
	buffer := make([]byte, size)

	for i := 0; i < size; i++ {
		buffer[i] = 'A' + byte(i%26)
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_writev"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdw)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("CharBufErrorBufTooLarge"))),
				ec.NewKprobeArgumentChecker().WithIntArg(1),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobe_char_iovec(t, configHook, checker, fdw, fdr, buffer)
}

func TestKprobe_char_iovec_returnCopy(t *testing.T) {
	fdw, fdr, _ := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write-read"
spec:
  kprobes:
  - call: "sys_readv"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_iovec"
      returnCopy: true
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fmt.Sprint(fdr)

	size := 4000
	buffer := make([]byte, size)

	for i := 0; i < size; i++ {
		buffer[i] = 'A' + byte(i%26)
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_readv"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdr)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full(buffer)),
				ec.NewKprobeArgumentChecker().WithSizeArg(8),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobe_char_iovec(t, configHook, checker, fdw, fdr, buffer)
}

func getMatchArgsFileCrd(opStr string, vals []string) string {
	configHook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "testing-file-match-args"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    return: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "` + opStr + `"
        values: `
	for i := 0; i < len(vals); i++ {
		configHook += fmt.Sprintf("\n        - \"%s\"", vals[i])
	}
	return configHook
}

func getMatchArgsFdCrd(opStr string, vals []string) string {
	configHook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "testing-file-match-args"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    return: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "` + opStr + `"
        values: `
	for i := 0; i < len(vals); i++ {
		configHook += fmt.Sprintf("\n        - \"%s\"", vals[i])
	}
	configHook += "\n"
	configHook += `      matchActions:
      - action: FollowFD
        argFd: 0
        argName: 1
  - call: "sys_close"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchActions:
      - action: UnfollowFD
        argFd: 0
        argName: 0
  - call: "sys_read"
    syscall: true
    args:
    - index: 0
      type: "fd"
    - index: 1
      type: "char_buf"
      returnCopy: false
    - index: 2
      type: "size_t"
    selectors:
    - matchArgs:
      - index: 0
        operator: "` + opStr + `"
        values: `
	for i := 0; i < len(vals); i++ {
		configHook += fmt.Sprintf("\n        - \"%s\"", vals[i])
	}
	return configHook
}

// this will trigger an fd_install event
func openFile(t *testing.T, file string) int {
	fd, errno := syscall.Open(file, syscall.O_RDONLY, 0)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd
}

// reads 32 bytes from a file, this will trigger a sys_read.
func readFile(t *testing.T, file string) int {
	fd := openFile(t, file)
	var readBytes = make([]byte, 32)
	i, errno := syscall.Read(fd, readBytes)
	if i < 0 {
		t.Logf("syscall.Read failed: %s\n", errno)
		t.Fatal()
	}
	return fd
}

func createFdInstallChecker(fd int, filename string) *ec.ProcessKprobeChecker {
	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("fd_install")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fd)),
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(filename))),
			))
	return kpChecker
}

func createReadChecker(t *testing.T, filename string) *ec.ProcessKprobeChecker {
	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_read"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(filename))),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte(""))), // returnCopy: false
				ec.NewKprobeArgumentChecker().WithSizeArg(32),
			))
	return kpChecker
}

func createCrdFile(t *testing.T, readHook string) {
	readConfigHook := []byte(readHook)
	err := os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
}

func getNumValues() int {
	if kernels.EnableLargeProgs() {
		return 4
	}
	return 2
}

func TestKprobeMatchArgsFileEqual(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	numValues := getNumValues()
	argVals := make([]string, numValues)
	argVals[0] = "/etc/passwd"
	argVals[1] = "/etc/group"
	if kernels.EnableLargeProgs() {
		argVals[2] = "/etc/hostname"
		argVals[3] = "/etc/shadow"
	}

	createCrdFile(t, getMatchArgsFileCrd("Equal", argVals[:]))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fds := make([]int, numValues)
	for i := 0; i < numValues; i++ {
		fds[i] = openFile(t, allFiles[i])
	}

	kpCheckers := make([]ec.EventChecker, numValues)
	for i, fd := range fds {
		kpCheckers[i] = createFdInstallChecker(fd, allFiles[i])
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeMatchArgsFilePostfix(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	numValues := getNumValues()
	argVals := make([]string, numValues)
	argVals[0] = "passwd"
	argVals[1] = "group"
	if kernels.EnableLargeProgs() {
		argVals[2] = "hostname"
		argVals[3] = "shadow"
	}

	createCrdFile(t, getMatchArgsFileCrd("Postfix", argVals[:]))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fds := make([]int, numValues)
	for i := 0; i < numValues; i++ {
		fds[i] = openFile(t, allFiles[i])
	}

	kpCheckers := make([]ec.EventChecker, numValues)
	for i, fd := range fds {
		kpCheckers[i] = createFdInstallChecker(fd, allFiles[i])
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeMatchArgsFilePrefix(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	numValues := getNumValues()
	argVals := make([]string, numValues)
	argVals[0] = "/etc/p"
	argVals[1] = "/etc/g"
	if kernels.EnableLargeProgs() {
		argVals[2] = "/etc/h"
		argVals[3] = "/etc/s"
	}

	createCrdFile(t, getMatchArgsFileCrd("Prefix", argVals[:]))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fds := make([]int, numValues)
	for i := 0; i < numValues; i++ {
		fds[i] = openFile(t, allFiles[i])
	}

	kpCheckers := make([]ec.EventChecker, numValues)
	for i, fd := range fds {
		kpCheckers[i] = createFdInstallChecker(fd, allFiles[i])
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeMatchArgsFdEqual(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	numValues := getNumValues()
	argVals := make([]string, numValues)
	argVals[0] = "/etc/passwd"
	argVals[1] = "/etc/group"
	if kernels.EnableLargeProgs() {
		argVals[2] = "/etc/hostname"
		argVals[3] = "/etc/shadow"
	}

	createCrdFile(t, getMatchArgsFdCrd("Equal", argVals[:]))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	kpCheckers := make([]ec.EventChecker, numValues)
	for i := 0; i < numValues; i++ {
		readFile(t, allFiles[i])
		kpCheckers[i] = createReadChecker(t, allFiles[i])
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeMatchArgsFdPostfix(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	numValues := getNumValues()
	argVals := make([]string, numValues)
	argVals[0] = "passwd"
	argVals[1] = "group"
	if kernels.EnableLargeProgs() {
		argVals[2] = "hostname"
		argVals[3] = "shadow"
	}

	createCrdFile(t, getMatchArgsFdCrd("Postfix", argVals[:]))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	kpCheckers := make([]ec.EventChecker, numValues)
	for i := 0; i < numValues; i++ {
		readFile(t, allFiles[i])
		kpCheckers[i] = createReadChecker(t, allFiles[i])
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeMatchArgsFdPrefix(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	numValues := getNumValues()
	argVals := make([]string, numValues)
	argVals[0] = "/etc/p"
	argVals[1] = "/etc/g"
	if kernels.EnableLargeProgs() {
		argVals[2] = "/etc/h"
		argVals[3] = "/etc/s"
	}

	createCrdFile(t, getMatchArgsFdCrd("Prefix", argVals[:]))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	kpCheckers := make([]ec.EventChecker, numValues)
	for i := 0; i < numValues; i++ {
		readFile(t, allFiles[i])
		kpCheckers[i] = createReadChecker(t, allFiles[i])
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func getMatchBinariesCrd(opStr string, vals []string) string {
	configHook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "testing-file-match-binaries"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    return: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchBinaries:
      - operator: "` + opStr + `"
        values: `
	for i := 0; i < len(vals); i++ {
		configHook += fmt.Sprintf("\n        - \"%s\"", vals[i])
	}
	return configHook
}

func createBinariesChecker(binary, filename string) *ec.ProcessKprobeChecker {
	kpChecker := ec.NewProcessKprobeChecker("").
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(binary))).
		WithFunctionName(sm.Full("fd_install")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Subset).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(filename))),
			))
	return kpChecker
}

func TestKprobeMatchBinariesIn(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, getMatchBinariesCrd("In", []string{"/usr/bin/cat"}))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command("/usr/bin/cat", "/etc/passwd").Run(); err != nil {
		t.Fatalf("failed to run cat /etc/passwd: %s", err)
	}

	if err := exec.Command("/usr/bin/head", "/etc/passwd").Run(); err != nil {
		t.Fatalf("failed to run head /etc/passwd: %s", err)
	}

	kpChecker := createBinariesChecker("/usr/bin/cat", "/etc/passwd")
	checker := ec.NewUnorderedEventChecker(kpChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeMatchBinariesNotIn(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, getMatchBinariesCrd("NotIn", []string{"/usr/bin/tail"}))

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command("/usr/bin/tail", "/etc/passwd").Run(); err != nil {
		t.Fatalf("failed to run cat /etc/passwd: %s", err)
	}

	if err := exec.Command("/usr/bin/head", "/etc/passwd").Run(); err != nil {
		t.Fatalf("failed to run head /etc/passwd: %s", err)
	}

	kpChecker := createBinariesChecker("/usr/bin/head", "/etc/passwd")
	checker := ec.NewUnorderedEventChecker(kpChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func loadTestCrd() error {
	testHook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
 name: "sys-write"
spec:
 kprobes:
 - call: "sys_write"
   syscall: true
`
	b := base.GetInitialSensor()
	if err := b.Load(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir); err != nil {
		return fmt.Errorf("load base sensor failed: %w", err)
	}

	tp, _ := tracingpolicy.PolicyFromYAML(testHook)
	if tp == nil {
		return nil
	}

	sens, err := sensors.GetMergedSensorFromParserPolicy(tp)
	if err != nil {
		return err
	}
	return sens.Load(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir)
}

func TestKprobeBpfAttr(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
 name: "bpf-check"
spec:
 kprobes:
 - call: "bpf_check"
   syscall: false
   args:
   - index: 1
     type: "bpf_attr"
`
	createCrdFile(t, hook)

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	err = loadTestCrd()
	if err != nil {
		t.Fatalf("Loading test CRD failed: %s", err)
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_check")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithBpfAttrArg(ec.NewKprobeBpfAttrChecker().
					WithProgName(sm.Full("generic_kprobe_")).
					WithProgType(sm.Full("BPF_PROG_TYPE_KPROBE")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadKprobeSensor(t *testing.T) {
	var sensorProgs = []tus.SensorProg{
		// kprobe
		0:  tus.SensorProg{Name: "generic_kprobe_event", Type: ebpf.Kprobe},
		1:  tus.SensorProg{Name: "generic_kprobe_process_event0", Type: ebpf.Kprobe},
		2:  tus.SensorProg{Name: "generic_kprobe_process_event1", Type: ebpf.Kprobe},
		3:  tus.SensorProg{Name: "generic_kprobe_process_event2", Type: ebpf.Kprobe},
		4:  tus.SensorProg{Name: "generic_kprobe_process_event3", Type: ebpf.Kprobe},
		5:  tus.SensorProg{Name: "generic_kprobe_process_event4", Type: ebpf.Kprobe},
		6:  tus.SensorProg{Name: "generic_kprobe_filter_arg1", Type: ebpf.Kprobe},
		7:  tus.SensorProg{Name: "generic_kprobe_filter_arg2", Type: ebpf.Kprobe},
		8:  tus.SensorProg{Name: "generic_kprobe_filter_arg3", Type: ebpf.Kprobe},
		9:  tus.SensorProg{Name: "generic_kprobe_filter_arg4", Type: ebpf.Kprobe},
		10: tus.SensorProg{Name: "generic_kprobe_filter_arg5", Type: ebpf.Kprobe},
		11: tus.SensorProg{Name: "generic_kprobe_process_filter", Type: ebpf.Kprobe},
		12: tus.SensorProg{Name: "generic_kprobe_actions", Type: ebpf.Kprobe},
		13: tus.SensorProg{Name: "generic_kprobe_output", Type: ebpf.Kprobe},
		// retkprobe
		14: tus.SensorProg{Name: "generic_retkprobe_event", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
		// all kprobe programs
		tus.SensorMap{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
		// all but generic_kprobe_output,generic_retkprobe_event
		tus.SensorMap{Name: "kprobe_calls", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},

		// only retkprobe
		tus.SensorMap{Name: "process_call_heap", Progs: []uint{14}},

		// generic_kprobe_process_filter,generic_kprobe_filter_arg*,
		// generic_kprobe_actions,generic_kprobe_output
		tus.SensorMap{Name: "filter_map", Progs: []uint{6, 7, 8, 9, 10, 11, 12}},

		// generic_kprobe_actions
		tus.SensorMap{Name: "override_tasks", Progs: []uint{12}},

		// all kprobe but generic_kprobe_process_filter,generic_retkprobe_event
		tus.SensorMap{Name: "config_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},

		// generic_kprobe_process_event*,generic_kprobe_actions,retkprobe
		tus.SensorMap{Name: "fdinstall_map", Progs: []uint{1, 2, 3, 4, 5, 12, 14}},
	}

	if kernels.EnableLargeProgs() {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 6, 7, 8, 9, 10, 11, 13, 14}})

		// generic_kprobe_process_event*,generic_kprobe_output,generic_retkprobe_event
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tcpmon_map", Progs: []uint{1, 2, 3, 4, 5, 13, 14}})

	} else {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 6, 7, 8, 9, 10, 11, 14}})

		// generic_kprobe_output,generic_retkprobe_event
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tcpmon_map", Progs: []uint{13, 14}})
	}

	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-read"
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
    return: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      returnCopy: true
    - index: 2
      type: "size_t"
    returnArg:
      type: "size_t"
`

	var sens []*sensors.Sensor
	var err error

	readConfigHook := []byte(readHook)
	err = os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	sens, err = observer.GetDefaultSensorsWithFile(t, context.TODO(), testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll()
}

func TestFakeSyscallError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testHook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
 name: "sys-fake"
spec:
 kprobes:
 - call: "sys_fake"
   syscall: true
`

	_, err := observer.GetDefaultObserverWithFile(t, ctx, "", tus.Conf().TetragonLib, observer.WithMyPid())
	assert.NoError(t, err)

	tp, err := tracingpolicy.PolicyFromYAML(testHook)
	assert.NoError(t, err)
	assert.NotNil(t, tp)

	sens, err := sensors.GetMergedSensorFromParserPolicy(tp)
	assert.Error(t, err)
	assert.Nil(t, sens)

	t.Logf("got error (as expected): %s", err)
}

func testMaxData(t *testing.T, data []byte, checker *eventchecker.UnorderedEventChecker, configHook string, fd int) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	writeConfigHook := []byte(configHook)
	err := os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	option.Config.RBSize = 1024 * 1024

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	_, err = syscall.Write(fd, data)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeWriteMaxDataTrunc(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestCopyFd requires at least 5.3.0 version")
	}
	_, fd2, fdString := createTestFile(t)
	myPid := observer.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fdString + `
`

	data := make([]byte, 6000)

	for i := 0; i < len(data); i++ {
		data[i] = 'a'
	}

	match := data[:4095]

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_write"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fd2)),
				ec.NewKprobeArgumentChecker().WithTruncatedBytesArg(
					ec.NewKprobeTruncatedBytesChecker().
						WithBytesArg(bc.Full(match)).
						WithOrigSize(uint64(len(data)))),
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(len(data))),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)
	testMaxData(t, data, checker, writeHook, fd2)
}

func TestKprobeWriteMaxData(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestCopyFd requires at least 5.3.0 version")
	}
	_, fd2, fdString := createTestFile(t)
	myPid := observer.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
      maxData: true
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fdString + `
`

	data := make([]byte, 6000)

	for i := 0; i < len(data); i++ {
		data[i] = 'a' + byte(i%26)
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_write"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fd2)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full(data)),
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(len(data))),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)
	testMaxData(t, data, checker, writeHook, fd2)
}

func TestKprobeWriteMaxDataFull(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestCopyFd requires at least 5.3.0 version")
	}
	_, fd2, fdString := createTestFile(t)
	myPid := observer.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
      maxData: true
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fdString + `
`

	// 10 times 32736 buffer is the max now
	data := make([]byte, 327360)

	for i := 0; i < len(data); i++ {
		data[i] = 'a' + byte(i%26)
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_write"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fd2)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full(data)),
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(len(data))),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)
	testMaxData(t, data, checker, writeHook, fd2)
}

func miniTcpNopServer(c chan<- bool) {
	conn, err := net.Listen("tcp4", "127.0.0.1:9919")
	if err != nil {
		panic(err)
	}
	c <- true
	ses, _ := conn.Accept()
	ses.Close()
	conn.Close()
}

func TestKprobeSock(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "DPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "9919"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)
	//conn.Close()

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919).
					WithProtocol(sm.Full("IPPROTO_TCP")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSkb(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "datagram"
spec:
  kprobes:
  - call: "__cgroup_bpf_run_filter_skb"
    syscall: false
    args:
    - index: 1
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 1
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 1
        operator: "DPort"
        values:
        - "53"
      - index: 1
        operator: "Protocol"
        values:
        - "IPPROTO_UDP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "datagram"
spec:
  kprobes:
  - call: "__cgroup_bpf_run_filter_skb"
    syscall: false
    args:
    - index: 1
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 1
        operator: "DPort"
        values:
        - "53"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dial := net.Dialer{}
			return dial.Dial("udp", "127.0.0.1:53")
		},
	}
	res.LookupIP(context.Background(), "ip4", "ebpf.io")

	kpChecker := ec.NewProcessKprobeChecker("datagram-checker").
		WithFunctionName(sm.Full("__cgroup_bpf_run_filter_skb")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLabel(sm.Full("datagram")).
					WithSkbArg(ec.NewKprobeSkbChecker().
						WithDaddr(sm.Full("127.0.0.1")).
						WithDport(53).
						WithProtocol(sm.Full("IPPROTO_UDP")),
					),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
