// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/ftrace"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	bc "github.com/cilium/tetragon/pkg/matchers/bytesmatcher"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/sensors/base"
	_ "github.com/cilium/tetragon/pkg/sensors/exec"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
kind: TracingPolicy
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
	_, err = observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	initialSensor := base.GetInitialSensor()
	initialSensor.Load(bpf.MapPrefixPath())
}

// NB: This is similar to TestKprobeObjectWriteRead, but it's a bit easier to
// debug because we can write things on stdout which will not generate events.
func TestKprobeLseek(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	t.Logf("tester pid=%s\n", pidStr)

	lseekConfigHook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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

	kpChecker := ec.NewProcessKprobeChecker("lseek-checker").
		WithFunctionName(sm.Suffix("sys_lseek"))

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(kpChecker))
	assert.NoError(t, err)
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	mntns, err := namespace.GetPidNsInode(myPid, "mnt")
	require.NoError(t, err)
	require.NotZero(t, mntns)
	mntNsStr := strconv.FormatUint(uint64(mntns), 10)
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
kind: TracingPolicy
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
	myPid := observertesthelper.GetMyPid()
	mntns, err := namespace.GetPidNsInode(myPid, "mnt")
	require.NoError(t, err)
	require.NotZero(t, mntns)
	mntNsStr := strconv.FormatUint(uint64(mntns), 10)
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	writeReadHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

// String matches should not require the '\0' null character on the end.
// Any '\0' null characters should be handled gracefully.
// Test with and without the null character.
func testKprobeObjectOpenHookFileName(withNull bool) string {
	if withNull {
		return `testfile\0`
	}
	return `testfile`
}

func testKprobeObjectOpenHook(pidStr string, path string, withNull bool) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
          - "` + path + `/` + testKprobeObjectOpenHookFileName(withNull) + `"
  `
}

func TestKprobeObjectOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectOpenHook(pidStr, dir, false)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectOpenWithNull(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectOpenHook(pidStr, dir, true)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectOpenHook(pidStr, dir, false)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectOpenMountWithNull(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectOpenHook(pidStr, dir, true)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeStringMatch(t *testing.T,
	readHook string,
	checker ec.MultiEventChecker,
	dir string) {

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	filePath := dir + "/testfile"

	readConfigHook := []byte(readHook)
	err := os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	syscall.Open(filePath, syscall.O_RDONLY, 0)
	err = jsonchecker.JsonTestCheckExpect(t, checker, false)
	assert.NoError(t, err)
}

func testKprobeStringMatchHook(pidStr string, dir string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
          - "` + dir + `/testfile"
  `
}

func TestKprobeStringMatchHash0Max(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 24
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash1Min(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 25
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash1Max(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 48
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash2Min(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 49
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash2Max(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 72
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash3Min(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 73
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash3Max(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 96
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash4Min(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 97
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash4Max(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 120
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash5Min(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 121
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash5Max(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 144
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash6Min(t *testing.T) {
	if !kernels.MinKernelVersion("5.4") {
		t.Skip("Test requires kernel 5.4+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 145
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash6Max(t *testing.T) {
	if !kernels.MinKernelVersion("5.4") {
		t.Skip("Test requires kernel 5.4+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 256
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash7Min(t *testing.T) {
	if !kernels.MinKernelVersion("5.4") {
		t.Skip("Test requires kernel 5.4+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 257
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash7Max(t *testing.T) {
	if !kernels.MinKernelVersion("5.4") {
		t.Skip("Test requires kernel 5.4+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 512
	if !kernels.MinKernelVersion("5.11") {
		pathLen = 510
	}
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash8Min(t *testing.T) {
	if !kernels.MinKernelVersion("5.11") {
		t.Skip("Test requires kernel 5.11+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 513
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash8Max(t *testing.T) {
	if !kernels.MinKernelVersion("5.11") {
		t.Skip("Test requires kernel 5.11+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 1024
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash9Min(t *testing.T) {
	if !kernels.MinKernelVersion("5.11") {
		t.Skip("Test requires kernel 5.11+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 1025
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash9Max(t *testing.T) {
	if !kernels.MinKernelVersion("5.11") {
		t.Skip("Test requires kernel 5.11+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 2048
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash10Min(t *testing.T) {
	if !kernels.MinKernelVersion("5.11") {
		t.Skip("Test requires kernel 5.11+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 2049
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func TestKprobeStringMatchHash10Max(t *testing.T) {
	if !kernels.MinKernelVersion("5.11") {
		t.Skip("Test requires kernel 5.11+")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	pathLen := 4096
	fileLen := len("/testfile")
	dir := strings.Repeat("A", pathLen-fileLen)
	readHook := testKprobeStringMatchHook(pidStr, dir)
	testKprobeStringMatch(t, readHook, getOpenatChecker(t, dir), dir)
}

func testKprobeObjectMultiValueOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
          - "` + path + `/foobar"
          - "` + path + `/testfile"
  `
}

func TestKprobeObjectMultiValueOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectMultiValueOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + dir + `/foofile"
`
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, dir, true, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectMultiValueFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + dir + `/foo"
        - "` + dir + `/bar"
`
	testKprobeObjectFiltered(t, readHook, getAnyChecker(), false, dir, true, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterPrefixOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixOpenSuperLong(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, dir)
	firstDir := dir + "/testfoo"
	longDir := firstDir + "/1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" +
		"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" +
		"123456789012345678901234567890123456789012345678901234567890"
	if err := os.Mkdir(firstDir, 0755); err != nil {
		t.Logf("Mkdir %s failed: %s\n", firstDir, err)
		t.Skip()
	}
	if err := os.Mkdir(longDir, 0755); err != nil {
		t.Logf("Mkdir %s failed: %s\n", longDir, err)
		t.Skip()
	}
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, longDir), false, longDir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterPrefixExactOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixExactOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterPrefixSubdirOpenHook(pidStr string, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixSubdirOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), true, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFilterPrefixMissOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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

// String matches should not require the '\0' null character on the end.
// Any '\0' null characters should be handled gracefully.
// Test with and without the null character.
func testKprobeObjectPostfixOpenFileName(withNull bool) string {
	if withNull {
		return `testfile\0`
	}
	return `testfile`
}

func testKprobeObjectPostfixOpen(t *testing.T, withNull bool) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + testKprobeObjectPostfixOpenFileName(withNull) + `"
`
	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, dir), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectPostfixOpen(t *testing.T) {
	testKprobeObjectPostfixOpen(t, false)
}

func TestKprobeObjectPostfixOpenWithNull(t *testing.T) {
	testKprobeObjectPostfixOpen(t, true)
}

func TestKprobeObjectPostfixOpenSuperLong(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + testKprobeObjectPostfixOpenFileName(false) + `"
`

	longDir := dir + "/1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" +
		"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" +
		"123456789012345678901234567890123456789012345678901234567890"
	if err := os.Mkdir(longDir, 0755); err != nil {
		t.Logf("Mkdir %s failed: %s\n", longDir, err)
		t.Skip()
	}

	testKprobeObjectFiltered(t, readHook, getOpenatChecker(t, longDir), false, longDir, false, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterModeOpenHook(pidStr string, mode int, valueFmt string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	checker := func(dir string) *ec.UnorderedEventChecker {
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	openHook := testKprobeObjectFilterModeOpenHook(pidStr, syscall.O_TRUNC, "%d")
	testKprobeObjectFiltered(t, openHook, getAnyChecker(), false, dir, true, syscall.O_RDWR, 0x770)
}

func testKprobeObjectFilterReturnValueGTHook(pidStr, path string) string {
	return `
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
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
          - "` + path + `"
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
  kind: TracingPolicy
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
          - "` + path + `"
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	fd2, _ := syscall.Open(path, syscall.O_RDWR, 0x770)
	t.Cleanup(func() { syscall.Close(fd2) })
	err = jsonchecker.JsonTestCheckExpect(t, checker, expectFailure)
	assert.NoError(t, err)
}

func TestKprobeObjectFilterReturnValueGTOk(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support GT/LT matching")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	path := dir + "/testfile"
	openHook := testKprobeObjectFilterReturnValueGTHook(pidStr, path)

	checker := func() *ec.UnorderedEventChecker {
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
	testKprobeObjectFilteredReturnValue(t, openHook, checker(), path, false /* OK */)
}

func TestKprobeObjectFilterReturnValueGTFail(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support GT/LT matching")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	path := dir + "/testfile"
	openHook := testKprobeObjectFilterReturnValueGTHook(pidStr, path)

	// testfile DOES NOT exist
	// we look for sys_openat(-100, "...testfile", ..) > 0
	testKprobeObjectFilteredReturnValue(t, openHook, getAnyChecker(), path, true /* FAIL */)
}

func TestKprobeObjectFilterReturnValueLTOk(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support GT/LT matching")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	path := dir + "/testfile"
	openHook := testKprobeObjectFilterReturnValueLTHook(pidStr, path)

	checker := func() *ec.UnorderedEventChecker {
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
	testKprobeObjectFilteredReturnValue(t, openHook, checker(), path, false /* OK */)
}

func TestKprobeObjectFilterReturnValueLTFail(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support GT/LT matching")
	}
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	writeReadHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
  kind: TracingPolicy
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
        - action: FollowFD
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
  kind: TracingPolicy
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
        - action: FollowFD
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(t, filepath.Join(dir, "testfile"), ""), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFileWriteFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, dir)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(t, filepath.Join(dir, "testfile"), ""), false, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFileWriteMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	dir := t.TempDir()
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, getWriteChecker(t, filepath.Join(dir, "testfile"), ""), true, dir, false, syscall.O_RDWR, 0x770)
}

func TestKprobeObjectFileWriteMountFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5")
	testMultipleMountsFiltered(t, readHook)
}

func TestMultiplePathComponents(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testMultiplePathComponentsFiltered(t, readHook)
}

func TestMultipleMountPath(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testMultipleMountPathFiltered(t, readHook)
}

func TestMultipleMountPathFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/7/8/9/10/11/12/13/14/15/16")
	if kernels.EnableLargeProgs() {
		readHook = testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16")
	}
	testMultipleMountPathFiltered(t, readHook)
}

func TestKprobeArgValues(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + file.Name() + `"
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

func TestKprobeOverrideSecurity(t *testing.T) {
	if !bpf.HasModifyReturn() {
		t.Skip("skipping fmod_ret support is not available")
	}

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-openat-override"
spec:
  options:
    - name: "disable-kprobe-multi"
      value: "1"
  kprobes:
  - call: "security_file_open"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    returnArg:
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
        - "` + file.Name() + `"
      matchActions:
      - action: Override
        argError: -2
`

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("security_file_open")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(file.Name()))),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-2)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	runKprobeOverride(t, openAtHook, checker, file.Name(), syscall.ENOENT, false)
}

func TestKprobeOverrideNopostAction(t *testing.T) {
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + file.Name() + `"
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + file.Name() + `"
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + file.Name() + `"
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	defer assert.NoError(t, file.Close())

	openAtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + file.Name() + `"
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

func runKprobeOverrideMulti(t *testing.T, hook string, checker ec.MultiEventChecker,
	testFile, testLink string, errOpen, errHardlink, errSymlink error) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	configHook := []byte(hook)
	err := os.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fd, err := syscall.Open(testFile, syscall.O_RDWR, 0x777)
	if fd >= 0 {
		t.Logf("syscall.Open succeeded\n")
		syscall.Close(fd)
		t.Fatal()
	}

	if !errors.Is(err, errOpen) {
		t.Fatalf("syscall.Open wrong error %v\n", err)
	}

	err = syscall.Link(testFile, testLink)
	if err == nil {
		t.Fatalf("syscall.Link succeeded\n")
	}

	if !errors.Is(err, errHardlink) {
		t.Fatalf("syscall.Link wrong error %v\n", err)
	}

	err = syscall.Symlink(testFile, testLink)
	if err == nil {
		t.Fatalf("syscall.Symlink succeeded\n")
	}

	if !errors.Is(err, errSymlink) {
		t.Fatalf("syscall.Symlink wrong error %v\n", err)
	}

	err = syscall.Rename(testFile, testLink)
	if err != nil {
		t.Fatalf("syscall.Rename failed\n")
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeOverrideMulti(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip()
	}

	if !bpf.HasOverrideHelper() {
		t.Skip("skipping override test, bpf_override_return helper not available")
	}

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	file, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("CreateTemp failed: %s", err)
	}
	defer assert.NoError(t, file.Close())

	link, err := os.CreateTemp(t.TempDir(), "kprobe-override-")
	if err != nil {
		t.Fatalf("CreateTemp failed: %s", err)
	}
	defer assert.NoError(t, link.Close())

	// The test hooks on 4 syscalls and override 3 of them.
	//
	//   sys_openat        override with -1
	//   sys_linkat        override with -2
	//   sys_symlinkat     override with -3
	//   sys_renameat      no override

	multiHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
        - "` + file.Name() + `"
      matchActions:
      - action: Override
        argError: -1
  - call: "sys_linkat"
    return: true
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
        - "` + file.Name() + `"
      matchActions:
      - action: Override
        argError: -2
  - call: "sys_symlinkat"
    syscall: true
    args:
    - index: 0
      type: "string"
    - index: 1
      type: "int"
    - index: 2
      type: "string"
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
        - "` + file.Name() + `"
      matchActions:
      - action: Override
        argError: -3
  - call: "sys_renameat"
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
        - "` + file.Name() + `"
`

	openChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_openat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-1)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)

	symlinkChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_linkat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(link.Name())),
				ec.NewKprobeArgumentChecker(),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-2)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)

	hardlinkChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_symlinkat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(link.Name())),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)

	renameChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_renameat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(file.Name())),
				ec.NewKprobeArgumentChecker(),
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Contains(link.Name())),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)

	checker := ec.NewUnorderedEventChecker(openChecker, symlinkChecker, hardlinkChecker, renameChecker)

	runKprobeOverrideMulti(t, multiHook, checker, file.Name(), link.Name(), syscall.EPERM, syscall.ENOENT, syscall.ESRCH)
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
	obs, err := observertesthelper.GetDefaultObserverWithWatchers(t, ctx, b, observertesthelper.WithConfig(testConfigFile), observertesthelper.WithLib(tus.Conf().TetragonLib), observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithWatchers error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
func readFile(t *testing.T, file string) {
	fd := openFile(t, file)
	var readBytes = make([]byte, 32)
	i, errno := syscall.Read(fd, readBytes)
	if i < 0 {
		t.Logf("syscall.Read failed: %s\n", errno)
		t.Fatal()
	}
}

func readMmapFile(t *testing.T, file string) {
	fd := openFile(t, file)
	data, errno := syscall.Mmap(fd, 0, 32, syscall.PROT_READ, syscall.MAP_FILE|syscall.MAP_SHARED)
	if errno != nil {
		t.Logf("syscall.Mmap failed: %s\n", errno)
		t.Fatal()
	}
	defer syscall.Munmap(data)
	// no need to copy data as we capture mmap call
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

func getMatchArgsFileFIMCrd(vals []string) string {
	configHook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values: `
	for _, f := range vals {
		configHook += fmt.Sprintf("\n        - \"%s\"", f)
	}
	return configHook
}

func TestKprobeMatchArgsFileMonitoringPrefix(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, getMatchArgsFileFIMCrd([]string{"/etc/"}))

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	kpCheckers := make([]ec.EventChecker, len(allFiles))
	for i, f := range allFiles {
		readFile(t, f)
		kpCheckers[i] = ec.NewProcessKprobeChecker("").
			WithFunctionName(sm.Full("security_file_permission")).
			WithArgs(ec.NewKprobeArgumentListMatcher().
				WithOperator(lc.Ordered).
				WithValues(
					ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(f))),
					ec.NewKprobeArgumentChecker().WithIntArg(4), // MAY_READ
				))
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeMatchArgsNonPrefix(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip()
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	configHook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values: 
        - "/etc/"
      - index: 0
        operator: "NotPrefix"
        values: 
        - "/etc/passwd"
        - "/etc/group"`

	createCrdFile(t, configHook)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	// read 4 files
	testFiles := [4]string{"/etc/passwd", "/etc/group", "/etc/hostname", "/etc/shadow"}
	for _, f := range testFiles {
		readFile(t, f)
	}

	// check that we get a read for  "/etc/hostname", and "/etc/shadow"
	kpCheckers := make([]ec.EventChecker, 2)
	for i := 2; i < len(testFiles); i++ {
		kpCheckers[i-2] = ec.NewProcessKprobeChecker("").
			WithFunctionName(sm.Full("security_file_permission")).
			WithArgs(ec.NewKprobeArgumentListMatcher().
				WithOperator(lc.Ordered).
				WithValues(
					ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(testFiles[i]))),
					ec.NewKprobeArgumentChecker().WithIntArg(4), // MAY_READ
				))
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	// now check that there is no read event for "/etc/passwd" and "/etc/group"
	kpErrCheckers := make([]ec.EventChecker, 2)
	for i := 0; i < len(testFiles)-2; i++ {
		kpErrCheckers[i] = ec.NewProcessKprobeChecker("").
			WithFunctionName(sm.Full("security_file_permission")).
			WithArgs(ec.NewKprobeArgumentListMatcher().
				WithOperator(lc.Ordered).
				WithValues(
					ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(testFiles[0]))),
					ec.NewKprobeArgumentChecker().WithIntArg(4), // MAY_READ
				))
	}

	errChecker := ec.NewUnorderedEventChecker(kpErrCheckers...)
	err = jsonchecker.JsonTestCheck(t, errChecker)
	assert.Error(t, err)
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

func matchBinariesTest(t *testing.T, operator string, values []string, kpChecker *ec.ProcessKprobeChecker) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, getMatchBinariesCrd(operator, values))

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command("/usr/bin/tail", "/etc/passwd").Run(); err != nil {
		t.Fatalf("failed to run tail /etc/passwd: %s", err)
	}

	if err := exec.Command("/usr/bin/head", "/etc/passwd").Run(); err != nil {
		t.Fatalf("failed to run head /etc/passwd: %s", err)
	}

	checker := ec.NewUnorderedEventChecker(kpChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

const skipMatchBinaries = "kernels without large progs do not support matchBinaries Prefix/NotPrefix/Postfix/NotPostfix"

func TestKprobeMatchBinaries(t *testing.T) {
	t.Run("In", func(t *testing.T) {
		matchBinariesTest(t, "In", []string{"/usr/bin/tail"}, createBinariesChecker("/usr/bin/tail", "/etc/passwd"))
	})
	t.Run("NotIn", func(t *testing.T) {
		matchBinariesTest(t, "NotIn", []string{"/usr/bin/tail"}, createBinariesChecker("/usr/bin/head", "/etc/passwd"))
	})
	t.Run("Prefix", func(t *testing.T) {
		if !kernels.EnableLargeProgs() {
			t.Skip(skipMatchBinaries)
		}
		matchBinariesTest(t, "Prefix", []string{"/usr/bin/t"}, createBinariesChecker("/usr/bin/tail", "/etc/passwd"))
	})
	t.Run("NotPrefix", func(t *testing.T) {
		if !kernels.EnableLargeProgs() {
			t.Skip(skipMatchBinaries)
		}
		matchBinariesTest(t, "NotPrefix", []string{"/usr/bin/t"}, createBinariesChecker("/usr/bin/head", "/etc/passwd"))
	})
	t.Run("Postfix", func(t *testing.T) {
		if !kernels.EnableLargeProgs() {
			t.Skip(skipMatchBinaries)
		}
		matchBinariesTest(t, "Postfix", []string{"bin/tail"}, createBinariesChecker("/usr/bin/tail", "/etc/passwd"))
	})
	t.Run("NotPostfix", func(t *testing.T) {
		if !kernels.EnableLargeProgs() {
			t.Skip(skipMatchBinaries)
		}
		matchBinariesTest(t, "NotPostfix", []string{"bin/tail"}, createBinariesChecker("/usr/bin/head", "/etc/passwd"))
	})
}

func matchBinariesLargePathTest(t *testing.T, operator string, values []string, binary string) {

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, getMatchBinariesCrd(operator, values))

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command(binary).Run(); err != nil {
		t.Fatalf("failed to run true: %s", err)
	}

	checker := ec.NewUnorderedEventChecker(ec.NewProcessKprobeChecker("").
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(binary))).
		WithFunctionName(sm.Full("fd_install")))
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

}
func TestKprobeMatchBinariesLargePath(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip()
	}

	// create a large temporary directory path
	tmpDir := t.TempDir()
	targetBinLargePath := tmpDir
	// add (255 + 1) * 15 = 3840 chars to the path
	// max is 4096 and we want to leave some space for the tmpdir + others
	for range 15 {
		targetBinLargePath += "/" + strings.Repeat("a", unix.NAME_MAX)
	}
	err := os.MkdirAll(targetBinLargePath, 0755)
	require.NoError(t, err)

	// copy the binary into it
	targetBinLargePath += "/true"
	fileExec, err := exec.LookPath("true")
	require.NoError(t, err)
	err = exec.Command("cp", fileExec, targetBinLargePath).Run()
	require.NoError(t, err)

	t.Run("Prefix", func(t *testing.T) {
		matchBinariesLargePathTest(t, "Prefix", []string{tmpDir}, targetBinLargePath)
	})
	t.Run("Postfix", func(t *testing.T) {
		matchBinariesLargePathTest(t, "Postfix", []string{"/true"}, targetBinLargePath)
	})
}

// matchBinariesPerfringTest checks that the matchBinaries do correctly
// filter the events i.e. it checks that no other events appear.
func matchBinariesPerfringTest(t *testing.T, operator string, values []string) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tus.GetTestSensorManager(ctx, t)

	matchBinariesTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "match-binaries",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call: "fd_install",
					Selectors: []v1alpha1.KProbeSelector{
						{
							MatchBinaries: []v1alpha1.BinarySelector{
								{
									Operator: operator,
									Values:   values,
								},
							},
						},
					},
				},
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &matchBinariesTracingPolicy)
	if assert.NoError(t, err) {
		t.Cleanup(func() {
			sm.Manager.DeleteTracingPolicy(ctx, "match-binaries", "")
		})
	}

	var tailPID, headPID int
	ops := func() {
		tailCmd := exec.Command("/usr/bin/tail", "/etc/passwd")
		headCmd := exec.Command("/usr/bin/head", "/etc/passwd")

		err := tailCmd.Start()
		assert.NoError(t, err)
		tailPID = tailCmd.Process.Pid
		err = headCmd.Start()
		assert.NoError(t, err)
		headPID = headCmd.Process.Pid

		err = tailCmd.Wait()
		assert.NoError(t, err)
		err = headCmd.Wait()
		assert.NoError(t, err)
	}
	events := perfring.RunTestEvents(t, ctx, ops)

	tailEventExist := false
	for _, ev := range events {
		if kprobe, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
			if int(kprobe.Msg.ProcessKey.Pid) == tailPID {
				tailEventExist = true
				continue
			}
			if int(kprobe.Msg.ProcessKey.Pid) == headPID {
				t.Error("kprobe event triggered by /usr/bin/head should be filtered by the matchBinaries selector")
				break
			}
		}
	}
	if !tailEventExist {
		t.Error("kprobe event triggered by /usr/bin/tail should be present, unfiltered by the matchBinaries selector")
	}
}

func TestKprobeMatchBinariesPerfring(t *testing.T) {
	t.Run("In", func(t *testing.T) {
		matchBinariesPerfringTest(t, "In", []string{"/usr/bin/tail"})
	})
	t.Run("Prefix", func(t *testing.T) {
		if !kernels.EnableLargeProgs() {
			t.Skip(skipMatchBinaries)
		}
		matchBinariesPerfringTest(t, "Prefix", []string{"/usr/bin/t"})
	})
	t.Run("Postfix", func(t *testing.T) {
		if !kernels.EnableLargeProgs() {
			t.Skip(skipMatchBinaries)
		}
		matchBinariesPerfringTest(t, "Postfix", []string{"tail"})
	})
}

// TestKprobeMatchBinariesEarlyExec checks that the matchBinaries can filter
// events triggered by process started before Tetragon.
func TestKprobeMatchBinariesEarlyExec(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	// create a temporary file
	file, err := os.CreateTemp("/tmp", fmt.Sprintf("tetragon.%s.", t.Name()))
	assert.NoError(t, err)
	t.Cleanup(func() {
		file.Close()
		os.Remove(file.Name())
	})
	// execute commands before Tetragon starts
	tailCommand := exec.Command("/usr/bin/tail", "-f", file.Name())
	err = tailCommand.Start()
	assert.NoError(t, err)
	defer tailCommand.Process.Kill()

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tus.GetTestSensorManager(ctx, t)

	matchBinariesTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "match-binaries",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call:    "sys_read",
					Syscall: true,
					Selectors: []v1alpha1.KProbeSelector{
						{
							MatchBinaries: []v1alpha1.BinarySelector{
								{
									Operator: "In",
									Values:   []string{"/usr/bin/tail"},
								},
							},
						},
					},
				},
			},
		},
	}

	err = sm.Manager.AddTracingPolicy(ctx, &matchBinariesTracingPolicy)
	if assert.NoError(t, err) {
		t.Cleanup(func() {
			sm.Manager.DeleteTracingPolicy(ctx, "match-binaries", "")
		})
	}

	ops := func() {
		file.WriteString("trigger!")
	}
	events := perfring.RunTestEvents(t, ctx, ops)

	for _, ev := range events {
		if kprobe, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
			if int(kprobe.Msg.ProcessKey.Pid) == tailCommand.Process.Pid && kprobe.FuncName == arch.AddSyscallPrefixTestHelper(t, "sys_read") {
				return
			}
		}
	}
	t.Error("events triggered by process executed before Tetragon should not be ignored because of matchBinaries")
}

// TestKprobeMatchBinariesPrefixMatchArgs makes sure that the prefix of
// matchBinaries works well with the prefix of matchArgs since its reusing some
// of its machinery.
func TestKprobeMatchBinariesPrefixMatchArgs(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip(skipMatchBinaries)
	}

	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tus.GetTestSensorManager(ctx, t)

	matchBinariesTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "match-binaries",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call:    "sys_openat",
					Syscall: true,
					Args: []v1alpha1.KProbeArg{
						{
							Index: 1,
							Type:  "string",
						},
					},
					Selectors: []v1alpha1.KProbeSelector{
						{
							MatchBinaries: []v1alpha1.BinarySelector{
								{
									Operator: "Prefix",
									Values:   []string{"/usr/bin/ta"},
								},
							},
							MatchArgs: []v1alpha1.ArgSelector{
								{
									Index:    1,
									Operator: "Prefix",
									Values:   []string{"/etc/pass"}, // not just /etc because of /etc/ld.so.cache
								},
							},
						},
					},
				},
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &matchBinariesTracingPolicy)
	if assert.NoError(t, err) {
		t.Cleanup(func() {
			sm.Manager.DeleteTracingPolicy(ctx, "match-binaries", "")
		})
	}

	var tailEtcPID, tailProcPID, headPID int
	ops := func() {
		tailEtcCmd := exec.Command("/usr/bin/tail", "/etc/passwd")
		tailProcCmd := exec.Command("/usr/bin/tail", "/proc/uptime")
		headCmd := exec.Command("/usr/bin/head", "/etc/passwd")

		err := tailEtcCmd.Start()
		assert.NoError(t, err)
		tailEtcPID = tailEtcCmd.Process.Pid
		err = tailProcCmd.Start()
		assert.NoError(t, err)
		tailProcPID = tailProcCmd.Process.Pid
		err = headCmd.Start()
		assert.NoError(t, err)
		headPID = headCmd.Process.Pid

		err = tailEtcCmd.Wait()
		assert.NoError(t, err)
		err = tailProcCmd.Wait()
		assert.NoError(t, err)
		err = headCmd.Wait()
		assert.NoError(t, err)
	}
	events := perfring.RunTestEvents(t, ctx, ops)

	tailEventExist := false
	for _, ev := range events {
		if kprobe, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
			if int(kprobe.Msg.ProcessKey.Pid) == tailEtcPID {
				tailEventExist = true
				continue
			}
			if int(kprobe.Msg.ProcessKey.Pid) == tailProcPID {
				t.Error("kprobe event triggered by \"/usr/bin/tail /proc/uptime\" should be filtered by the matchArgs selector")
				break
			}
			if int(kprobe.Msg.ProcessKey.Pid) == headPID {
				t.Error("kprobe event triggered by /usr/bin/head should be filtered by the matchBinaries selector")
				break
			}
		}
	}
	if !tailEventExist {
		t.Error("kprobe event triggered by /usr/bin/tail should be present, unfiltered by the matchBinaries selector")
	}
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

	tp, _ := tracingpolicy.FromYAML(testHook)
	if tp == nil {
		return nil
	}

	sens, err := sensors.GetMergedSensorFromParserPolicy(tp)
	if err != nil {
		return err
	}
	err = sens.Load(option.Config.BpfDir)
	if err != nil {
		return err
	}
	return sens.Unload()
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
		0: tus.SensorProg{Name: "generic_kprobe_event", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "generic_kprobe_setup_event", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "generic_kprobe_process_event", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: "generic_kprobe_filter_arg", Type: ebpf.Kprobe},
		4: tus.SensorProg{Name: "generic_kprobe_process_filter", Type: ebpf.Kprobe},
		5: tus.SensorProg{Name: "generic_kprobe_actions", Type: ebpf.Kprobe},
		6: tus.SensorProg{Name: "generic_kprobe_output", Type: ebpf.Kprobe},
		// retkprobe
		7:  tus.SensorProg{Name: "generic_retkprobe_event", Type: ebpf.Kprobe},
		8:  tus.SensorProg{Name: "generic_retkprobe_filter_arg", Type: ebpf.Kprobe},
		9:  tus.SensorProg{Name: "generic_retkprobe_actions", Type: ebpf.Kprobe},
		10: tus.SensorProg{Name: "generic_retkprobe_output", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
		// all kprobe programs
		tus.SensorMap{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},

		// all but generic_kprobe_output
		tus.SensorMap{Name: "kprobe_calls", Progs: []uint{0, 1, 2, 3, 4, 5}},

		// generic_retkprobe_event
		tus.SensorMap{Name: "retkprobe_calls", Progs: []uint{7, 8, 9}},

		// generic_kprobe_process_filter,generic_kprobe_filter_arg,
		// generic_kprobe_actions,generic_kprobe_output
		tus.SensorMap{Name: "filter_map", Progs: []uint{3, 4, 5}},

		// generic_kprobe_actions
		tus.SensorMap{Name: "override_tasks", Progs: []uint{5}},

		// all kprobe but generic_kprobe_process_filter,generic_retkprobe_event
		tus.SensorMap{Name: "config_map", Progs: []uint{0, 1, 2}},

		// generic_kprobe_process_event*,generic_kprobe_actions,retkprobe
		tus.SensorMap{Name: "fdinstall_map", Progs: []uint{1, 2, 5, 7, 9}},

		// generic_kprobe_event
		tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}},
	}

	if kernels.EnableLargeProgs() {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4, 5, 6, 7, 9}})

		// generic_kprobe_process_event*,generic_kprobe_output,generic_retkprobe_output
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tcpmon_map", Progs: []uint{1, 2, 6, 10}})

		// generic_kprobe_process_event*,generic_kprobe_actions,retkprobe
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "socktrack_map", Progs: []uint{1, 2, 5, 7, 9}})
	} else {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4, 7}})

		// generic_kprobe_output,generic_retkprobe_output
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tcpmon_map", Progs: []uint{6, 10}})
	}

	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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

	var err error
	readConfigHook := []byte(readHook)
	err = os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
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

	_, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, "", tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	assert.NoError(t, err)

	tp, err := tracingpolicy.FromYAML(testHook)
	assert.NoError(t, err)
	assert.NotNil(t, tp)

	sens, err := sensors.GetMergedSensorFromParserPolicy(tp)
	assert.Error(t, err)
	assert.Nil(t, sens)

	t.Logf("got error (as expected): %s", err)
}

func testMaxData(t *testing.T, data []byte, checker *ec.UnorderedEventChecker, configHook string, fd int) {
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	writeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	miniTcpNopServerWithPort(c, 9919, false)
}

func miniTcpNopServer6(c chan<- bool) {
	miniTcpNopServerWithPort(c, 9919, true)
}

func miniTcpNopServerWithPort(c chan<- bool, port int, ipv6 bool) {
	var conn net.Listener
	var err error
	if !ipv6 {
		conn, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	} else {
		conn, err = net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
	}
	if err != nil {
		panic(err)
	}
	c <- true
	ses, _ := conn.Accept()
	ses.Close()
	conn.Close()
}

func TestKprobeSockBasic(t *testing.T) {
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockNotPort(t *testing.T) {
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
        operator: "NotDPort"
        values:
        - "9918"
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
        operator: "NotDPort"
        values:
        - "9918"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockMultiplePorts(t *testing.T) {
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
        - "9910"
        - "9919"
        - "9925"
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
        - "9910"
        - "9919"
        - "9925"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockPortRange(t *testing.T) {
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
        - "9910:9920"
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
        - "9910:9920"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockPrivPorts(t *testing.T) {
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
        operator: "DPortPriv"
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
        operator: "DPortPriv"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServerWithPort(tcpReady, 1020, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:1020")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(1020),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockNotPrivPorts(t *testing.T) {
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
        operator: "NotDPortPriv"
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
        operator: "NotDPortPriv"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockNotCIDR(t *testing.T) {
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
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
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
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockMultipleCIDRs(t *testing.T) {
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
        - "10.0.0.1"
        - "127.0.0.1"
        - "172.16.0.0/16"
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
        operator: "DAddr"
        values:
        - "10.0.0.1"
        - "127.0.0.1"
        - "172.16.0.0/16"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockState(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-set-state"
spec:
  kprobes:
  - call: "tcp_set_state"
    syscall: false
    args:
    - index: 0
      type: "sock"
    - index: 1
      type: "int"
      label: "state"
    selectors:
    - matchArgs:
      - index: 0
        operator: "SAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "SPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
      - index: 0
        operator: "State"
        values:
        - "TCP_SYN_RECV"
      - index: 1
        operator: "Equal"
        values:
        - 1
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-set-state"
spec:
  kprobes:
  - call: "tcp_set_state"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "State"
        values:
        - "TCP_SYN_RECV"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-state-checker").
		WithFunctionName(sm.Full("tcp_set_state")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithSaddr(sm.Full("127.0.0.1")).
					WithSport(9919).
					WithState(sm.Full("TCP_SYN_RECV")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSockFamily(t *testing.T) {
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
      - index: 0
        operator: "Family"
        values:
        - "AF_INET"
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
        operator: "Family"
        values:
        - "AF_INET"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919).
					WithFamily(sm.Full("AF_INET")),
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
  - call: "ip_send_skb"
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
  - call: "ip_send_skb"
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			dial := net.Dialer{}
			return dial.Dial("udp", "127.0.0.1:53")
		},
	}
	res.LookupIP(context.Background(), "ip4", "ebpf.io")

	kpChecker := ec.NewProcessKprobeChecker("datagram-checker").
		WithFunctionName(sm.Full("ip_send_skb")).
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

func TestKprobeSockIpv6(t *testing.T) {
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
        - "::1"
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
        operator: "DAddr"
        values:
        - "::1"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer6(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "[::1]:9919")
	assert.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	assert.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("::1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSkbIpv6(t *testing.T) {
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
  - call: "ip6_send_skb"
    syscall: false
    args:
    - index: 0
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "::1"
      - index: 0
        operator: "DPort"
        values:
        - "53"
      - index: 0
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
  - call: "ip6_send_skb"
    syscall: false
    args:
    - index: 0
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "::1"
`

	if kernels.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			dial := net.Dialer{}
			return dial.Dial("udp", "[::1]:53")
		},
	}
	res.LookupIP(context.Background(), "ip4", "ebpf.io")

	kpChecker := ec.NewProcessKprobeChecker("datagram-checker").
		WithFunctionName(sm.Full("ip6_send_skb")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLabel(sm.Full("datagram")).
					WithSkbArg(ec.NewKprobeSkbChecker().
						WithDaddr(sm.Full("::1")).
						WithDport(53).
						WithProtocol(sm.Full("IPPROTO_UDP")),
					),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testKprobeRateLimit(t *testing.T, rateLimit bool) {
	hook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "datagram"
spec:
  kprobes:
  - call: "ip_send_skb"
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
        - "9468"
      - index: 1
        operator: "Protocol"
        values:
        - "IPPROTO_UDP"
`

	if rateLimit {
		hook += `
      matchActions:
      - action: Post
        rateLimit: "5"
        rateLimitScope: "global"
`
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, hook)
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	server := "nc.openbsd"
	cmdServer := exec.Command(server, "-unvlp", "9468", "-s", "127.0.0.1")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1 * time.Second)

	// Generate 5 datagrams
	socket, err := net.Dial("udp", "127.0.0.1:9468")
	if err != nil {
		t.Fatalf("failed dialing socket: %s", err)
	}

	for i := 0; i < 5; i++ {
		_, err := socket.Write([]byte("data"))
		if err != nil {
			t.Fatalf("failed writing to socket: %s", err)
		}
	}

	kpChecker := ec.NewProcessKprobeChecker("datagram-checker").
		WithFunctionName(sm.Full("ip_send_skb")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLabel(sm.Full("datagram")).
					WithSkbArg(ec.NewKprobeSkbChecker().
						WithDaddr(sm.Full("127.0.0.1")).
						WithDport(9468).
						WithProtocol(sm.Full("IPPROTO_UDP")),
					),
			))

	var checkerSuccess *ec.UnorderedEventChecker
	var checkerFailure *ec.UnorderedEventChecker
	if rateLimit {
		// Rate limit. We should have 1. We shouldn't have 2 (or more)
		checkerSuccess = ec.NewUnorderedEventChecker(kpChecker)
		checkerFailure = ec.NewUnorderedEventChecker(kpChecker, kpChecker)
	} else {
		// No rate limit. We should have 5. We shouldn't have 6.
		checkerSuccess = ec.NewUnorderedEventChecker(kpChecker, kpChecker, kpChecker, kpChecker, kpChecker)
		checkerFailure = ec.NewUnorderedEventChecker(kpChecker, kpChecker, kpChecker, kpChecker, kpChecker, kpChecker)
	}
	cmdServer.Process.Kill()

	err = jsonchecker.JsonTestCheck(t, checkerSuccess)
	assert.NoError(t, err)
	err = jsonchecker.JsonTestCheckExpect(t, checkerFailure, true)
	assert.NoError(t, err)
}

func TestKprobeNoRateLimit(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Test requires kernel 5.4")
	}

	testKprobeRateLimit(t, false)
}

func TestKprobeRateLimit(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Test requires kernel 5.4")
	}

	testKprobeRateLimit(t, true)
}

func TestKprobeListSyscallDupsRange(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestCopyFd requires at least 5.3.0 version")
	}
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write"
spec:
  lists:
  kprobes:
  - call: "sys_dup"
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
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - 9910:9920
`

	// The test hooks sys_dup syscall and filters for fd
	// in range 9910 to 9920.

	checker := ec.NewUnorderedEventChecker()

	for i := 9910; i < 9920; i++ {
		kpCheckerDup := ec.NewProcessKprobeChecker("").
			WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_dup"))).
			WithArgs(ec.NewKprobeArgumentListMatcher().
				WithOperator(lc.Ordered).
				WithValues(
					ec.NewKprobeArgumentChecker().WithIntArg(int32(i)),
				))

		checker.AddChecks(kpCheckerDup)
	}

	testListSyscallsDupsRange(t, checker, configHook)
}

// This just tests if the hooks that we are using in our
// trace kernel module examples are stable enough
func TestTraceKernelModuleCallsStability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "monitor-kernel-modules"
spec:
  kprobes:
  - call: "do_init_module"
    syscall: false
    args:
    - index: 0
      type: "module"
  - call: "free_module"
    syscall: false
    args:
    - index: 0
      type: "module"
`
	createCrdFile(t, hookFull)

	_, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
}

func TestLinuxBinprmExtractPath(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support matchArgs with linux_binprm")
	}
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tus.GetTestSensorManager(ctx, t)

	bprmTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "bprm-extract-path",
		},
		Spec: v1alpha1.TracingPolicySpec{
			Options: []v1alpha1.OptionSpec{
				{
					Name:  "disable-kprobe-multi",
					Value: "1",
				},
			},
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call:    "security_bprm_check",
					Syscall: false,
					Return:  false,
					Args: []v1alpha1.KProbeArg{
						{
							Index: 0,
							Type:  "linux_binprm",
						},
					},
					Selectors: []v1alpha1.KProbeSelector{
						{
							MatchArgs: []v1alpha1.ArgSelector{
								{
									Operator: "Equal",
									Index:    0,
									Values:   []string{"/usr/bin/id"},
								},
							},
						},
					},
				},
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &bprmTracingPolicy)
	if assert.NoError(t, err) {
		t.Cleanup(func() {
			sm.Manager.DeleteTracingPolicy(ctx, "bprm-extract-path", "")
		})
	}

	targetCommand := exec.Command("/usr/bin/id")
	filteredCommand := exec.Command("/usr/bin/uname")

	ops := func() {
		err = targetCommand.Start()
		assert.NoError(t, err)
		err = filteredCommand.Start()
		assert.NoError(t, err)
		defer targetCommand.Process.Kill()
		defer filteredCommand.Process.Kill()
	}

	events := perfring.RunTestEvents(t, ctx, ops)

	wantedEventExist := false
	for _, ev := range events {
		if kprobe, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
			if int(kprobe.Msg.ProcessKey.Pid) == targetCommand.Process.Pid {
				wantedEventExist = true
				continue
			}
			if int(kprobe.Msg.ProcessKey.Pid) == filteredCommand.Process.Pid {
				t.Error("kprobe event triggered by /usr/bin/uname should be filtered by the matchArgs selector")
				break
			}
		}
	}
	if !wantedEventExist {
		t.Error("kprobe event triggered by /usr/bin/id should be present, unfiltered by the matchArgs selector")
	}
}

// Test module loading/unloading on Ubuntu
func TestTraceKernelModule(t *testing.T) {
	_, err := ftrace.ReadAvailFuncs("^find_module_sections$")
	if err != nil {
		t.Skip("Skipping test: could not find find_module_sections")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "monitor-kernel-modules"
spec:
  kprobes:
  - call: "security_kernel_read_file"
    # Explicit module loading using file descriptor finit_module() to print module full path
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "2"  # READING_MODULE
  - call: "find_module_sections"
    # On some kernels find_module_sections is inlined, if so this kprobe will fail.
    syscall: false
    args:
    - index: 0
      type: "nop"
    - index: 1
      type: "load_info"
  - call: "do_init_module"
    syscall: false
    args:
    - index: 0
      type: "module"
  - call: "free_module"
    syscall: false
    args:
    - index: 0
      type: "module"
`

	// This test works only on Ubuntu
	f, err := os.Open("/etc/os-release")
	if err != nil {
		t.Skip("Skipping test: could not parse /etc/os-release file")
	}
	defer f.Close()

	ubuntu := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Ubuntu") {
			ubuntu = true
			break
		}
	}

	if ubuntu == false {
		t.Skip("Skipping test: could not determin if this is an Ubuntu machine")
	}

	createCrdFile(t, hookFull)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	module := "nfsv4"
	var stdout, stderr bytes.Buffer
	testCmd := exec.CommandContext(ctx, "/usr/sbin/modprobe", module)
	testCmd.Stdout = &stdout
	testCmd.Stderr = &stderr
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		stderr := stderr.String()
		t.Fatalf("Load '%s' module failed with %s. Context error: %v, error output: %v", module, err, ctx.Err(), stderr)
	}
	if len(stdout.String()) > 0 {
		t.Logf("Load '%s' module  stdout:\n%v\n", module, stdout.String())
	}

	testCmd = exec.CommandContext(ctx, "/usr/sbin/modprobe", "-r", module)
	testCmd.Stdout = &stdout
	testCmd.Stderr = &stderr
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		stderr := stderr.String()
		t.Fatalf("Unload '%s' module failed with %s. Context error: %v, error output: %v", module, err, ctx.Err(), stderr)
	}
	if len(stdout.String()) > 0 {
		t.Logf("Unload '%s' module stdout:\n%v\n", module, stdout.String())
	}

	process := ec.NewProcessChecker().
		WithBinary(sm.Suffix("modprobe"))

	kpChecker1 := ec.NewProcessKprobeChecker("").WithProcess(process).
		WithFunctionName(sm.Full("security_kernel_read_file")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(
					ec.NewKprobeFileChecker().
						WithPath(sm.Contains(fmt.Sprintf("%s.ko", module)))),
				ec.NewKprobeArgumentChecker().WithIntArg(2),
			),
		)

	kpChecker2 := ec.NewProcessKprobeChecker("").WithProcess(process).
		WithFunctionName(sm.Full("find_module_sections")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithModuleArg(
					ec.NewKernelModuleChecker().WithName(sm.Contains(module)).
						WithSignatureOk(true)),
			),
		)

	kpChecker3 := ec.NewProcessKprobeChecker("").WithProcess(process).
		WithFunctionName(sm.Full("do_init_module")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithModuleArg(
					ec.NewKernelModuleChecker().WithName(sm.Contains(module)),
				),
			))

	kpChecker4 := ec.NewProcessKprobeChecker("").WithProcess(process).
		WithFunctionName(sm.Full("free_module")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithModuleArg(
					ec.NewKernelModuleChecker().WithName(sm.Contains(module)),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker1, kpChecker2, kpChecker3, kpChecker4)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeKernelStackTrace(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	tracingPolicy := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: uname
spec:
  kprobes:
    - call: sys_newuname
      selectors:
      - matchActions:
        - action: Post
          kernelStackTrace: true`

	createCrdFile(t, tracingPolicy)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	unameBin := "/usr/bin/uname"

	if err := exec.Command(unameBin).Run(); err != nil {
		t.Fatalf("failed to run %s: %s", unameBin, err)
	}

	stackTraceChecker := ec.NewProcessKprobeChecker("kernel-stack-trace").
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(unameBin))).
		WithKernelStackTrace(ec.NewStackTraceEntryListMatcher().WithValues(
			ec.NewStackTraceEntryChecker().WithSymbol(sm.Suffix(("sys_newuname"))),
			// we could technically check for more but stack traces look
			// different on different archs, at least we check that the stack
			// trace is enabled, works and exports something coherent
			//
			// syscall  /usr/bin/uname __x64_sys_newuname
			//   0x0: __x64_sys_newuname+0x5
			//   0x0: entry_SYSCALL_64_after_hwframe+0x72
			//
			// syscall  /usr/bin/uname __arm64_sys_newuname
			//   0x0: __do_sys_newuname+0x2f0
			//   0x0: el0_svc_common.constprop.0+0x180
			//   0x0: do_el0_svc+0x30
			//   0x0: el0_svc+0x48
			//   0x0: el0t_64_sync_handler+0xa4
			//   0x0: el0t_64_sync+0x1a4
		))

	checker := ec.NewUnorderedEventChecker(stackTraceChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
func TestKprobeUserStackTrace(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()
	testUserStacktrace := testutils.RepoRootPath("contrib/tester-progs/user-stacktrace")
	tracingPolicy := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "test-user-stacktrace"
spec:
  kprobes:
  - call: "sys_getcpu"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testUserStacktrace + `"
      matchActions:
      - action: Post
        userStackTrace: true`

	createCrdFile(t, tracingPolicy)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	test_cmd := exec.Command(testUserStacktrace)

	if err := test_cmd.Start(); err != nil {
		t.Fatalf("failed to run %s: %s", testUserStacktrace, err)
	}

	stackTraceChecker := ec.NewProcessKprobeChecker("user-stack-trace").
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(testUserStacktrace)))
	if kernels.MinKernelVersion("5.15.0") {
		stackTraceChecker = stackTraceChecker.WithUserStackTrace(ec.NewStackTraceEntryListMatcher().WithValues(
			ec.NewStackTraceEntryChecker().WithModule(sm.Suffix(("contrib/tester-progs/user-stacktrace"))),
			ec.NewStackTraceEntryChecker().WithSymbol(sm.Suffix(("main.main"))),
			// syscall user-nix /home/user/go/src/github.com/cilium/tetragon/contrib/tester-progs/user-stacktrace __x64_sys_getcpu
			// User:
			//   0x0: runtime/internal/syscall.Syscall6 (/home/user/go/src/github.com/cilium/tetragon/contrib/tester-progs/user-stacktrace+0x2aee)
			//   0x0: syscall.Syscall (/home/user/go/src/github.com/cilium/tetragon/contrib/tester-progs/user-stacktrace+0x63346)
			//   0x0: syscall.Syscall.abi0 (/home/user/go/src/github.com/cilium/tetragon/contrib/tester-progs/user-stacktrace+0x634ae)
			//   0x0: main.main (/home/user/go/src/github.com/cilium/tetragon/contrib/tester-progs/user-stacktrace+0x6503e)
			//   0x0: runtime.main (/home/user/go/src/github.com/cilium/tetragon/contrib/tester-progs/user-stacktrace+0x3313d)
			//   0x0: runtime.goexit.abi0 (/home/user/go/src/github.com/cilium/tetragon/contrib/tester-progs/user-stacktrace+0x5e661)
		))
	} else {
		// For kernels below 5.15 user stack trace information gathered from bpf might be not full
		stackTraceChecker = stackTraceChecker.WithUserStackTrace(ec.NewStackTraceEntryListMatcher().WithValues(
			ec.NewStackTraceEntryChecker().WithModule(sm.Suffix(("contrib/tester-progs/user-stacktrace"))),
		))
	}

	checker := ec.NewUnorderedEventChecker(stackTraceChecker)
	err = jsonchecker.JsonTestCheck(t, checker)

	// Kill test because of endless loop in the test for stable stack trace extraction
	test_cmd.Process.Kill()

	assert.NoError(t, err)
}

func TestKprobeMultiMatcArgs(t *testing.T) {
	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support matchArgs for more than one arguments")
	}

	tracingPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring-filtered"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    message: "Access sensitive files /etc/passwd"
    tags: [ "observability.filesystem" ]
    args:
    - index: 0
      type: "file" # (struct file *) used for getting the path
    - index: 1
      type: "int" # 0x04 is MAY_READ, 0x02 is MAY_WRITE
    returnArg:
      index: 0
      type: "int"
    returnArgAction: "Post"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd"
      - index: 1
        operator: "Equal"
        values:
        - "4" # MAY_READ
  - call: "security_mmap_file"
    syscall: false
    return: true
    message: "Access sensitive files /etc/shadow"
    tags: [ "observability.filesystem" ]
    args:
    - index: 0
      type: "file" # (struct file *) used for getting the path
    - index: 1
      type: "uint32" # the prot flags PROT_READ(0x01), PROT_WRITE(0x02), PROT_EXEC(0x04)
    - index: 2
      type: "nop" # the mmap flags (i.e. MAP_SHARED, ...)
    returnArg:
      index: 0
      type: "int"
    returnArgAction: "Post"
    selectors:
    - matchArgs:      
      - index: 0
        operator: "Equal"
        values:
        - "/etc/shadow"
      - index: 1
        operator: "Equal"
        values:
        - "1" # MAY_READ
`

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, tracingPolicy)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	// read with system call /etc/passwd
	readFile(t, "/etc/passwd")

	// read with mmap /etc/shadow
	readMmapFile(t, "/etc/shadow")

	kpCheckersRead := ec.NewProcessKprobeChecker("").
		WithMessage(sm.Full("Access sensitive files /etc/passwd")).
		WithTags(ec.NewStringListMatcher().WithValues(sm.Full("observability.filesystem"))).
		WithFunctionName(sm.Full("security_file_permission")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full("/etc/passwd"))),
				ec.NewKprobeArgumentChecker().WithIntArg(4),
			))

	kpCheckersMmap := ec.NewProcessKprobeChecker("").
		WithMessage(sm.Full("Access sensitive files /etc/shadow")).
		WithTags(ec.NewStringListMatcher().WithValues(sm.Full("observability.filesystem"))).
		WithFunctionName(sm.Full("security_mmap_file")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full("/etc/shadow"))),
				ec.NewKprobeArgumentChecker().WithUintArg(1),
			))

	checker := ec.NewUnorderedEventChecker(kpCheckersRead, kpCheckersMmap)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func trigger(t *testing.T) {
	ins := asm.Instructions{
		// Return SK_DROP
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "test",
		Type:         ebpf.Tracing,
		AttachType:   ebpf.AttachTraceFEntry,
		Instructions: ins,
		License:      "MIT",
		AttachTo:     "bpf_modify_return_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	opts := ebpf.RunOptions{}
	ret, err := prog.Run(&opts)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Fatalf("Expected return value to be 0, got %d", ret)
	}
}

func TestKprobeArgs(t *testing.T) {
	_, err := ftrace.ReadAvailFuncs("^bpf_fentry_test1$")
	if err != nil {
		t.Skip("Skipping test: could not find bpf_fentry_test1")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	t.Logf("tester pid=%s\n", pidStr)

	hook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "bpf_fentry_test1"
    syscall: false
    args:
    - index: 0
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
  - call: "bpf_fentry_test2"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
  - call: "bpf_fentry_test3"
    syscall: false
    args:
    - index: 0
      type: "int8"
    - index: 1
      type: "int"
    - index: 2
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
  - call: "bpf_fentry_test4"
    syscall: false
    args:
    - index: 0
      type: "uint64"
    - index: 1
      type: "int8"
    - index: 2
      type: "int"
    - index: 3
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
  - call: "bpf_fentry_test5"
    syscall: false
    args:
    - index: 0
      type: "uint64"
    - index: 1
      type: "uint64"
    - index: 2
      type: "int16"
    - index: 3
      type: "int"
    - index: 4
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
`

	createCrdFile(t, hook)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	trigger(t)

	check1 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test1")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
			))

	check2 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test2")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(2),
				ec.NewKprobeArgumentChecker().WithSizeArg(3),
			))

	check3 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test3")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(4),
				ec.NewKprobeArgumentChecker().WithIntArg(5),
				ec.NewKprobeArgumentChecker().WithSizeArg(6),
			))

	check4 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test4")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(7),
				ec.NewKprobeArgumentChecker().WithIntArg(8),
				ec.NewKprobeArgumentChecker().WithIntArg(9),
				ec.NewKprobeArgumentChecker().WithSizeArg(10),
			))

	check5 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test5")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(11),
				ec.NewKprobeArgumentChecker().WithSizeArg(12),
				ec.NewKprobeArgumentChecker().WithIntArg(13),
				ec.NewKprobeArgumentChecker().WithIntArg(14),
				ec.NewKprobeArgumentChecker().WithSizeArg(15),
			))

	checker := ec.NewUnorderedEventChecker(check1, check2, check3, check4, check5)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// Detect changing capabilities
func TestProcessSetCap(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	tracingPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "privileges-raise"
  annotations:
    description: "Detects privileges change operations"
spec:
  kprobes:
  - call: "security_capset"
    syscall: false
    message: "Process changed its capabilities with capset system call"
    args:
    - index: 0
      type: "nop"
    - index: 1
      type: "cred"
    - index: 2
      type: "cap_effective"
    - index: 3
      type: "cap_inheritable"
    - index: 4
      type: "cap_permitted"
    selectors:
    - matchArgs:
      - index: 2
        operator: "NotEqual"
        values:
        - "0"
    - matchArgs:
      - index: 4
        operator: "NotEqual"
        values:
        - "0"
`

	createCrdFile(t, tracingPolicy)

	fullSet := caps.GetCapsFullSet()
	firstChange := fullSet&0xffffffff00000000 | uint64(0xffdfffff)  // Removes CAP_SYS_ADMIN
	secondChange := fullSet&0xffffffff00000000 | uint64(0xffdffffe) // removes CAP_SYS_ADMIN and CAP_CHOWN

	_, currentPermitted, currentEffective, _ := caps.GetPIDCaps(filepath.Join(option.Config.ProcFS, fmt.Sprint(os.Getpid()), "status"))

	if currentPermitted == 0 || currentPermitted != currentEffective {
		t.Skip("Skipping test since current Permitted or Effective capabilities are zero or do not match")
	}

	// Now we ensure at least that we have the full capabilities set active
	if caps.AreSubset(fullSet, currentPermitted) == false ||
		caps.AreSubset(fullSet, currentEffective) == false {
		// full capabilities set is not set in current permitted
		t.Skipf("Skipping test since current Permitted or Effective capabilities are not a full capabilities set %s - %s",
			caps.GetCapabilitiesHex(currentPermitted), caps.GetCapabilitiesHex(currentEffective))
	}

	lastCap, _ := caps.GetCapability(caps.GetLastCap())
	t.Logf("Test %s running with last capability:%d  %s", t.Name(), caps.GetLastCap(), lastCap)
	t.Logf("Test %s running with cap_permitted:%s  -  cap_effective:%s",
		t.Name(), caps.GetCapabilitiesHex(currentPermitted), caps.GetCapabilitiesHex(currentEffective))

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testSetCaps := testutils.RepoRootPath("contrib/tester-progs/change-capabilities")

	t.Logf("Test %s Matching cap_permitted:%s - cap_inheritable:%s - cap_effective:%s",
		t.Name(), caps.GetCapabilitiesHex(fullSet), fmt.Sprintf("%016x", 0), caps.GetCapabilitiesHex(firstChange))
	kpCheckers1 := ec.NewProcessKprobeChecker("").
		WithMessage(sm.Full("Process changed its capabilities with capset system call")).
		WithFunctionName(sm.Full("security_capset")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				// effective caps
				ec.NewKprobeArgumentChecker().WithCapEffectiveArg(sm.Full(caps.GetCapabilitiesHex(firstChange))),
				// inheritable
				ec.NewKprobeArgumentChecker().WithCapInheritableArg(sm.Full(fmt.Sprintf("%016x", 0))),
				// permitted
				ec.NewKprobeArgumentChecker().WithCapPermittedArg(sm.Full(caps.GetCapabilitiesHex(fullSet))),
			))

	t.Logf("Test %s Matching cap_permitted:%s - cap_inheritable:%s - cap_effective:%s",
		t.Name(), caps.GetCapabilitiesHex(fullSet), fmt.Sprintf("%016x", 0), caps.GetCapabilitiesHex(secondChange))
	kpCheckers2 := ec.NewProcessKprobeChecker("").
		WithMessage(sm.Full("Process changed its capabilities with capset system call")).
		WithFunctionName(sm.Full("security_capset")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				// effective caps
				ec.NewKprobeArgumentChecker().WithCapEffectiveArg(sm.Full(caps.GetCapabilitiesHex(secondChange))),
				// inheritable
				ec.NewKprobeArgumentChecker().WithCapInheritableArg(sm.Full(fmt.Sprintf("%016x", 0))),
				// permitted
				ec.NewKprobeArgumentChecker().WithCapPermittedArg(sm.Full(caps.GetCapabilitiesHex(fullSet))),
			))

	testCmd := exec.CommandContext(ctx, testSetCaps)
	var output, errput bytes.Buffer
	testCmd.Stdout = &output
	testCmd.Stderr = &errput
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		stderr := errput.String()
		t.Fatalf("command failed with %s. Context error: %v, error output: %v", err, ctx.Err(), stderr)
	}
	if len(output.String()) > 0 {
		t.Logf("Test %s command '%s' stdout:\n%v\n", t.Name(), testSetCaps, output.String())
	}

	checker := ec.NewUnorderedEventChecker(kpCheckers1, kpCheckers2)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestMissedProgStatsKprobeMulti(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	// we need kernel support to count the prog's missed count added in:
	// f915fcb38553 ("bpf: Count stats for kprobe_multi programs")
	// which was added in v6.7, adding also the kprobe-multi check
	// just to be sure we have that
	if !kernels.MinKernelVersion("6.7") || !bpf.HasKprobeMulti() {
		t.Skip("Test requires kprobe multi and kernel version 6.7")
	}

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	tracingPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "syswritefollowfdpsswd"
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testNop + `"
      matchActions:
      - action: Signal
        argSig: 10
  - call: "group_send_sig_info"
    syscall: false
`

	createCrdFile(t, tracingPolicy)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command(testNop).Run(); err != nil {
		fmt.Printf("Failed to execute test binary: %s\n", err)
	}

	expected := strings.NewReader(` # HELP tetragon_missed_prog_probes_total The total number of Tetragon probe missed by program.
# TYPE tetragon_missed_prog_probes_total counter
tetragon_missed_prog_probes_total{attach="acct_process",policy="__base__"} 0
tetragon_missed_prog_probes_total{attach="kprobe_multi (2 functions)",policy="syswritefollowfdpsswd"} 1
tetragon_missed_prog_probes_total{attach="sched/sched_process_exec",policy="__base__"} 0
tetragon_missed_prog_probes_total{attach="security_bprm_committing_creds",policy="__base__"} 0
tetragon_missed_prog_probes_total{attach="wake_up_new_task",policy="__base__"} 0
`)

	assert.NoError(t, testutil.GatherAndCompare(metricsconfig.GetRegistry(), expected,
		prometheus.BuildFQName(consts.MetricsNamespace, "", "missed_prog_probes_total")))

}
