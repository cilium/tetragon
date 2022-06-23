// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	bc "github.com/cilium/tetragon/pkg/matchers/bytesmatcher"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/namespace"

	"github.com/cilium/tetragon/pkg/sensors/base"
	_ "github.com/cilium/tetragon/pkg/sensors/exec"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var mountPath = "/tmp2"

const (
	testConfigFile = "/tmp/tetragon.gotest.yaml"
	kprobeTestDir  = "/sys/fs/bpf/testObserver/"
)

func TestKprobeObjectLoad(t *testing.T) {
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_write"
spec:
  kprobes:
  - call: "__x64_sys_write"
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
	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	_, err = observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	initialSensor := base.GetInitialSensor()
	initialSensor.Load(context.TODO(), kprobeTestDir, kprobeTestDir, "")
}

// NB: This is similar to TestKprobeObjectWriteRead, but it's a bit easier to
// debug because we can write things on stdout which will not generate events.
func TestKprobeLseek(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	fmt.Printf("pid=%s\n", pidStr)

	lseekConfigHook_ := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_write"
spec:
  kprobes:
  - call: "__x64_sys_lseek"
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
	err := ioutil.WriteFile(testConfigFile, lseekConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)
}

func getTestKprobeObjectWRChecker() ec.MultiEventChecker {
	myNs := ec.NewNamespacesChecker().FromNamespaces(namespace.GetCurrentNamespace())
	myCaps := ec.NewCapabilitiesChecker().FromCapabilities(caps.GetCurrentCapabilities())

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_write")).
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

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	checker := getTestKprobeObjectWRChecker()

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
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
  name: "sys_write"
spec:
  kprobes:
  - call: "__x64_sys_write"
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
  name: "sys_write"
spec:
  kprobes:
  - call: "__x64_sys_write"
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
  name: "sys_write"
spec:
  kprobes:
  - call: "__x64_sys_write"
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
  name: "sys_write"
spec:
  kprobes:
  - call: "__x64_sys_write"
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
  name: "sys_write"
spec:
  kprobes:
  - call: "__x64_sys_write"
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

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
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
  name: "sys_read"
spec:
  kprobes:
  - call: "__x64_sys_read"
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

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_read")).
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
  name: "sys_read"
spec:
  kprobes:
  - call: "__x64_sys_read"
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

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_read")).
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

// __x64_sys_openat trace
func getOpenatChecker() ec.MultiEventChecker {
	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_openat")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(-100),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("/tmp/testfile")),
				ec.NewKprobeArgumentChecker(),
			))

	return ec.NewUnorderedEventChecker(kpChecker)
}

// __x64_sys_openat trace
func getOpenatMntChecker() ec.MultiEventChecker {
	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_openat")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(-100),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(mountPath+"/testfile")),
				ec.NewKprobeArgumentChecker(),
			))

	return ec.NewUnorderedEventChecker(kpChecker)
}

// matches any kprobe event, used to test filters
func getAnyChecker() ec.MultiEventChecker {
	return ec.NewUnorderedEventChecker(ec.NewProcessKprobeChecker())
}

func testKprobeObjectFiltered(t *testing.T,
	readHook string,
	checker ec.MultiEventChecker,
	useMount bool,
	expectFailure bool) {

	mntPath := "/tmp"
	if useMount == true {
		mntPath = mountPath

		if err := os.Mkdir(mntPath, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
		if err := syscall.Mount("tmpfs", mntPath, "tmpfs", 0, ""); err != nil {
			t.Logf("Mount failed: %s\n", err)
			t.Skip()
		}
		t.Cleanup(func() {
			if err := syscall.Unmount(mntPath, 0); err != nil {
				t.Logf("Unmount failed: %s\n", err)
			}
			if err := os.Remove(mntPath); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
		})
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
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
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
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
	err = jsonchecker.JsonTestCheck(t, checker)
	if expectFailure {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

func testKprobeObjectOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys_read"
  spec:
    kprobes:
    - call: "__x64_sys_openat"
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
	readHook := testKprobeObjectOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(), false, false)
}

func TestKprobeObjectOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, getOpenatMntChecker(), true, false)
}

func testKprobeObjectMultiValueOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys_read"
  spec:
    kprobes:
    - call: "__x64_sys_openat"
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
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(), false, false)
}

func TestKprobeObjectMultiValueOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, getOpenatMntChecker(), true, false)
}

func TestKprobeObjectFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_read"
spec:
  kprobes:
  - call: "__x64_sys_openat"
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
        - "/tmp/foofile\0"
`
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, true)
}

func TestKprobeObjectMultiValueFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_read"
spec:
  kprobes:
  - call: "__x64_sys_openat"
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
        - "/tmp/foo\0"
        - "/tmp/bar\0"
`
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, true)
}

func testKprobeObjectFilterPrefixOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys_read"
  spec:
    kprobes:
    - call: "__x64_sys_openat"
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
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(), false, false)
}

func TestKprobeObjectFilterPrefixOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, getOpenatMntChecker(), true, false)
}

func testKprobeObjectFilterPrefixExactOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys_read"
  spec:
    kprobes:
    - call: "__x64_sys_openat"
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
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(), false, false)
}

func TestKprobeObjectFilterPrefixExactOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, getOpenatMntChecker(), true, false)
}

func testKprobeObjectFilterPrefixSubdirOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys_read"
  spec:
    kprobes:
    - call: "__x64_sys_openat"
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
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(), false, false)
}

func TestKprobeObjectFilterPrefixSubdirOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, getOpenatMntChecker(), true, false)
}

func TestKprobeObjectFilterPrefixMissOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_read"
spec:
  kprobes:
  - call: "__x64_sys_openat"
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
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, true)
}

func TestKprobeObjectPostfixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_read"
spec:
  kprobes:
  - call: "__x64_sys_openat"
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
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(), false, false)
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

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	writeReadHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "__x64_sys_writev"
spec:
  kprobes:
  - call: "__x64_sys_writev"
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
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kpChecker := ec.NewProcessKprobeChecker().
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(selfBinary))).
		WithFunctionName(sm.Full("__x64_sys_writev")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("hello iovec world"))),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
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

func getFilpOpenChecker() ec.MultiEventChecker {
	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("do_filp_open")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(-100),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("/tmp/testfile")),
			))

	return ec.NewUnorderedEventChecker(kpChecker)
}

func TestKprobeObjectFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_read"
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
	testKprobeObjectFiltered(t, readHook, getFilpOpenChecker(), false, false)
}

func TestKprobeObjectReturnFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys_read"
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
	testKprobeObjectFiltered(t, readHook, getFilpOpenChecker(), false, false)
}

func testKprobeObjectFileWriteHook(pidStr string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  metadata:
    name: "sys_read"
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
    - call: "__x64_sys_write"
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
    name: "sys_read"
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
    - call: "__x64_sys_write"
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

func getWriteChecker(path, flags string) ec.MultiEventChecker {
	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_write")).
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
			WithBinary(sm.Suffix(selfBinary)))

	return ec.NewUnorderedEventChecker(kpChecker)
}

func TestKprobeObjectFileWrite(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, getWriteChecker("/tmp/testfile", ""), false, false)
}

func TestKprobeObjectFileWriteFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, getWriteChecker("/tmp/testfile", ""), false, false)
}

func TestKprobeObjectFileWriteMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(mountPath+"/testfile", ""), true, false)
}

func TestKprobeObjectFileWriteMountFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(mountPath+"/testfile", ""), true, false)
}

func corePathTest(t *testing.T, filePath string, readHook string, writeChecker ec.MultiEventChecker) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	// Create file to open later
	fd, errno := syscall.Open(filePath, syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Close(fd)

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
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

	writeChecker := getWriteChecker("/tmp2/tmp3/tmp4/tmp5/testfile", "")

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
	writeChecker := getWriteChecker("/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = getWriteChecker("/tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
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
	writeChecker := getWriteChecker("/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = getWriteChecker("/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
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
  name: "sys_linkat_args"
spec:
  kprobes:
  - call: "__x64_sys_linkat"
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

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_linkat")).
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

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
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
	testFile string, testErr error) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	if !bpf.HasOverrideHelper() {
		t.Skip("skipping override test, bpf_override_return helper not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	configHook := []byte(hook)
	err := ioutil.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, tetragonLib)
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
	assert.NoError(t, err)
}

func TestKprobeOverride(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	file, err := ioutil.TempFile("/tmp", "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer os.Remove(file.Name())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "__x64_sys_openat override"
spec:
  kprobes:
  - call: "__x64_sys_openat"
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

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_openat")).
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

	runKprobeOverride(t, openAtHook, checker, file.Name(), syscall.ENOENT)
}

func TestKprobeOverrideNonSyscall(t *testing.T) {
	closeFdHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "close_fd override"
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
	err := ioutil.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	_, err = observer.GetDefaultObserverWithFileNoTest(t, testConfigFile, tetragonLib, true)
	if err == nil {
		t.Fatalf("GetDefaultObserverWithFileNoTest ok, should fail\n")
	}
	assert.Error(t, err)
}

func runKprobe_char_iovec(t *testing.T, configHook string,
	checker *ec.UnorderedEventChecker, fdw, fdr int, buffer []byte) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testConfigHook := []byte(configHook)
	err := ioutil.WriteFile(testConfigFile, testConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithWatchers(t, observer.WithConfig(testConfigFile), observer.WithLib(tetragonLib))
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
  name: "sys_write_writev"
spec:
  kprobes:
  - call: "__x64_sys_writev"
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

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_writev")).
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
  name: "sys_write_writev"
spec:
  kprobes:
  - call: "__x64_sys_writev"
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

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_writev")).
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
  name: "sys_write_read"
spec:
  kprobes:
  - call: "__x64_sys_readv"
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

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_readv")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdr)),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full(buffer)),
				ec.NewKprobeArgumentChecker().WithIntArg(8),
			))
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobe_char_iovec(t, configHook, checker, fdw, fdr, buffer)
}
