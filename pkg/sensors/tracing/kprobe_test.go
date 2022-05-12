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

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/pkg/bpf"
	ec "github.com/cilium/tetragon/pkg/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"

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
apiVersion: hubble-enterprise.io/v1
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
	_, err = observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	initialSensor := sensors.GetInitialSensor()
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
apiVersion: hubble-enterprise.io/v1
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

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)
}

func getTestKprobeObjectWRChecker() ec.MultiResponseChecker {
	myNs := namespace.GetCurrentNamespace()
	myCaps := caps.GetCurrentCapabilities()
	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(1),
			ec.GenericArgBytesCheck([]byte("hello world")),
			ec.GenericArgSizeCheck(11),
		}).
		WithNs(myNs).
		WithCaps(myCaps, ec.CapsInheritable).
		WithCaps(myCaps, ec.CapsEffective).
		WithCaps(myCaps, ec.CapsPermitted)
	return ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)
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

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	_, err = syscall.Write(1, []byte("hello world"))
	assert.NoError(t, err)

	err = observer.JsonTestCheck(t, checker)
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
apiVersion: hubble-enterprise.io/v1
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
apiVersion: hubble-enterprise.io/v1
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

func TestKprobeObjectWriteReadNsOnly(t *testing.T) {
	myPid := observer.GetMyPid()
	mntNsStr := strconv.FormatUint(uint64(namespace.GetPidNsInode(myPid, "mnt")), 10)
	writeReadHook := `
apiVersion: hubble-enterprise.io/v1
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
apiVersion: hubble-enterprise.io/v1
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

func runKprobeObjectRead(t *testing.T, readHook string, checker ec.MultiResponseChecker, fd, fd2 int) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
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

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeObjectRead(t *testing.T) {
	fd, fd2, fdString := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_read").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(int32(fd2)),
			ec.GenericArgBytesCheck([]byte("hello world")),
			ec.GenericArgSizeCheck(100),
		})
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	runKprobeObjectRead(t, readHook, &checker, fd, fd2)
}

func TestKprobeObjectReadReturn(t *testing.T) {
	fd, fd2, fdString := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_read").
		WithArgsReturn([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(int32(fd2)),
			ec.GenericArgBytesCheck([]byte("hello world")),
			ec.GenericArgSizeCheck(100)},
			ec.GenericArgSizeCheck(11),
		)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	runKprobeObjectRead(t, readHook, &checker, fd, fd2)
}

// __x64_sys_openat trace
var (
	openArg0Check    = ec.GenericArgIntCheck(-100)
	openArg1Check    = ec.GenericArgStringCheck("/tmp/testfile")
	openArg1CheckMnt = ec.GenericArgStringCheck(mountPath + "/testfile")
	openArg2Check    = ec.GenericArgIsInt()

	openKprobeCheck = ec.NewKprobeChecker().
			WithFunctionName("__x64_sys_openat").
			WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1Check, openArg2Check})

	openKprobeCheckMnt = ec.NewKprobeChecker().
				WithFunctionName("__x64_sys_openat").
				WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1CheckMnt, openArg2Check})

	openChecker = ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(openKprobeCheck).
			End(),
	)

	openCheckerMnt = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(openKprobeCheckMnt).
			End(),
	)

	// this check fails if it find a kprobe event. It is used to test filters.
	noKprobeChecker = ec.NewAllMultiResponseChecker(
		ec.ResponseCheckerFn(
			func(r *fgs.GetEventsResponse, l ec.Logger) error {
				switch ev := r.Event.(type) {
				case *fgs.GetEventsResponse_ProcessKprobe:
					return fmt.Errorf("Unexpected event: %+v", ev)
				default:
					return nil
				}
			},
		),
	)
)

func testKprobeObjectFiltered(t *testing.T,
	readHook string,
	checker ec.MultiResponseChecker,
	useMount bool) {

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

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
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
	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testKprobeObjectOpenHook(pidStr string, path string) string {
	return `
  apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func testKprobeObjectMultiValueOpenHook(pidStr string, path string) string {
	return `
  apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectMultiValueOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func TestKprobeObjectFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker, false)
}

func TestKprobeObjectMultiValueFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker, false)
}

func testKprobeObjectFilterPrefixOpenHook(pidStr string, path string) string {
	return `
  apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectFilterPrefixOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func testKprobeObjectFilterPrefixExactOpenHook(pidStr string, path string) string {
	return `
  apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectFilterPrefixExactOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func testKprobeObjectFilterPrefixSubdirOpenHook(pidStr string, path string) string {
	return `
  apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectFilterPrefixSubdirOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func TestKprobeObjectFilterPrefixMissOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker, false)
}

func TestKprobeObjectPostfixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
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
apiVersion: hubble-enterprise.io/v1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_writev").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(1),
			ec.GenericArgBytesCheck([]byte("hello iovec world")),
		})

	checker := ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(kpChecker).
			End(),
	)

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = helloIovecWorldWritev()
	assert.NoError(t, err)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

var (
	doOpenKprobeCheck = ec.NewKprobeChecker().
				WithFunctionName("do_filp_open").
				WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1Check})

	doOpenChecker = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(doOpenKprobeCheck).
			End(),
	)
)

func TestKprobeObjectFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, doOpenChecker, false)
}

func TestKprobeObjectReturnFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
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
	testKprobeObjectFiltered(t, readHook, doOpenChecker, false)
}

func testKprobeObjectFileWriteHook(pidStr string) string {
	return `
  apiVersion: hubble-enterprise.io/v1
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
  apiVersion: hubble-enterprise.io/v1
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

var (
	writeArg0    = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch("/tmp/testfile"), ec.FullStringMatch(""))
	writeArg0Mnt = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch(mountPath+"/testfile"), ec.FullStringMatch(""))
	writeArg1    = ec.GenericArgBytesCheck([]byte("hello world"))
	writeArg2    = ec.GenericArgSizeCheck(11)

	writeFileKpChecker = ec.NewKprobeChecker().
				WithFunctionName("__x64_sys_write").
				WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2})

	writeChecker = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(writeFileKpChecker).
			End(),
	)

	writeFileKpCheckerMnt = ec.NewKprobeChecker().
				WithFunctionName("__x64_sys_write").
				WithArgs([]ec.GenericArgChecker{writeArg0Mnt, writeArg1, writeArg2})

	writeCheckerMnt = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(writeFileKpCheckerMnt).
			End(),
	)
)

func TestKprobeObjectFileWrite(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, writeChecker, false)
}

func TestKprobeObjectFileWriteFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, writeChecker, false)
}

func TestKprobeObjectFileWriteMount(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, writeCheckerMnt, true)
}

func TestKprobeObjectFileWriteMountFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, writeCheckerMnt, true)
}

func createWriteChecker(path string, flags string) ec.MultiResponseChecker {
	writeArg0 = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch(path), ec.FullStringMatch(flags))
	writeArg1 = ec.GenericArgBytesCheck([]byte("hello world"))
	writeArg2 = ec.GenericArgSizeCheck(11)

	writeFileKpChecker = ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2})

	writeChecker = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(writeFileKpChecker).
			End(),
	)

	return writeChecker
}

func corePathTest(t *testing.T, filePath string, readHook string, writeChecker ec.MultiResponseChecker) {
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

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
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
	err = observer.JsonTestCheck(t, writeChecker)
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

	writeChecker = createWriteChecker("/tmp4/tmp5/testfile", "unresolvedMountPoints")
	if kernels.EnableLargeProgs() {
		writeChecker = createWriteChecker("/tmp2/tmp3/tmp4/tmp5/testfile", "")
	}

	// the full path name is "/tmp2/tmp3/tmp4/tmp5/testfile"
	// but in the current implementation we support up to 2 mount points
	// so we will see "/tmp4/tmp5/testfile" and "unresolvedMountPoints" flag

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
	writeChecker = createWriteChecker("/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = createWriteChecker("/tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
	}

	// the full path name is "/tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16"
	// but in the current implementation we support up to 13 path components
	// so we will see "/5/6/7/8/9/10/11/12/13/14/15/16/testfile"
	// and "unresolvedPathComponents" flag

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
	writeChecker = createWriteChecker("/[M]/tmp4/tmp5/[P]/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedMountPoints unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = createWriteChecker("/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
	}

	// the full path name is "/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile"
	// but in the current implementation we support up to 13 path components and 2 mount points
	// so we will see "/tmp4/tmp5/5/6/7/8/9/10/11/12/13/14/15/16/testfile"
	// and "unresolvedMountPoints unresolvedPathComponents"

	corePathTest(t, filePath, readHook, writeChecker)
}

func TestMultipleMountsFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp4/tmp5")
	if kernels.EnableLargeProgs() {
		readHook = testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5")
	}
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
	// Kernel adds a & in the case of unresolved path. In the userspace we change that to [P]
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp4/tmp5/&/7/8/9/10/11/12/13/14/15/16")
	if kernels.EnableLargeProgs() {
		readHook = testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16")
	}
	testMultipleMountPathFiltered(t, readHook)
}

func TestKprobeArgValues(t *testing.T) {
	pidStr := strconv.Itoa(int(observer.GetMyPid()))
	readHook := `
apiVersion: isovalent.com/v1alpha1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_linkat").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(oldFd),
			ec.GenericArgStringCheck(oldFile),
			ec.GenericArgIntCheck(newFd),
			ec.GenericArgStringCheck(newFile),
			ec.GenericArgIntCheck(flags),
		})
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
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

	err = observer.JsonTestCheck(t, &checker)
	assert.NoError(t, err)
}

// override

func runKprobeOverride(t *testing.T, hook string, checker ec.MultiResponseChecker,
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

	obs, err := observer.GetDefaultObserverWithFile(t, testConfigFile, fgsLib)
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

	err = observer.JsonTestCheck(t, checker)
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
apiVersion: hubble-enterprise.io/v1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_openat").
		WithArgsReturn([]ec.GenericArgChecker{
			ec.GenericArgIsInt(),
			ec.GenericArgStringCheck(file.Name()),
			ec.GenericArgIsInt()},
			ec.GenericArgIntCheck(-2)).
		WithAction(fgs.KprobeAction_KPROBE_ACTION_OVERRIDE)

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	runKprobeOverride(t, openAtHook, &checker, file.Name(), syscall.ENOENT)
}

func TestKprobeOverrideNonSyscall(t *testing.T) {
	closeFdHook := `
apiVersion: hubble-enterprise.io/v1
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

	_, err = observer.GetDefaultObserverWithFileNoTest(t, testConfigFile, fgsLib, true)
	if err == nil {
		t.Fatalf("GetDefaultObserverWithFileNoTest ok, should fail\n")
	}
	assert.Error(t, err)
}

func runKprobe_char_iovec(t *testing.T, configHook string,
	checker *ec.OrderedMultiResponseChecker, fdw, fdr int, buffer []byte) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testConfigHook := []byte(configHook)
	err := ioutil.WriteFile(testConfigFile, testConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithWatchers(t, observer.WithConfig(testConfigFile), observer.WithLib(fgsLib))
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

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobe_char_iovec(t *testing.T) {
	fdw, fdr, _ := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	configHook := `
apiVersion: hubble-enterprise.io/v1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_writev").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(int32(fdw)),
			ec.GenericArgBytesCheck(buffer),
			ec.GenericArgIntCheck(1),
		})
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	runKprobe_char_iovec(t, configHook, &checker, fdw, fdr, buffer)
}

func TestKprobe_char_iovec_overflow(t *testing.T) {
	fdw, fdr, _ := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	configHook := `
apiVersion: hubble-enterprise.io/v1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_writev").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(int32(fdw)),
			ec.GenericArgBytesCheck([]byte("CharBufErrorBufTooLarge")),
			ec.GenericArgIntCheck(1),
		})
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	runKprobe_char_iovec(t, configHook, &checker, fdw, fdr, buffer)
}

func TestKprobe_char_iovec_returnCopy(t *testing.T) {
	fdw, fdr, _ := createTestFile(t)
	pidStr := strconv.Itoa(int(observer.GetMyPid()))

	configHook := `
apiVersion: hubble-enterprise.io/v1
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

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_readv").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(int32(fdr)),
			ec.GenericArgBytesCheck(buffer),
			ec.GenericArgSizeCheck(8),
		})
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	runKprobe_char_iovec(t, configHook, &checker, fdw, fdr, buffer)
}
