// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	proc "github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorExec")
	os.Exit(ec)
}

func Test_msgToExecveKubeUnix(t *testing.T) {
	event := processapi.MsgExecveEvent{}
	idLength := procevents.BpfContainerIdLength

	// Minikube has "docker-" prefix.
	prefix := "docker-"
	minikubeID := prefix + "9e123a99b140a6ea4a8d15040ca2c8ee2d5ee9605e81d66ae4e3e29c3f0ef220.scope"
	copy(event.Kube.Docker[:], minikubeID)
	kube := msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(minikubeID, "-")[1][:idLength], kube.Docker)
	event.Kube.Docker[0] = 0
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)

	// GKE doesn't.
	gkeID := "82836ef3675020258bee5075ace6264b3bc5300e20c975543cbc984bea59638f"
	copy(event.Kube.Docker[:], gkeID)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, gkeID[:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))
	event.Kube.Docker[0] = 0
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)

	id := "kubepods-burstable-pod29349498_197c_4919_b13f_9a928e7d001b.slice:cri-containerd:0ca2b3cd20e5f55a2bbe8d4aa3f811cf7963b40f0542ad147054b0fcb60fc400"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, id[80:80+idLength], kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = "kubepods-besteffort-pod13cb8437-00ed-40e4-99d8-e17193a58086.slice:cri-containerd:a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, id[81:81+idLength], kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = "cri-containerd-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(id, "-")[2][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = "libpod-01f3c60cfaadbb51e4d5947dd2ef0480d53551cbcee8f3ada8c3723b2bf03bf4"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(id, "-")[1][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = ":a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(id, ":")[1][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	// Empty event so we don't fail tests
	for i := 0; i < processapi.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	// Not valid
	id = "ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)

	// Empty event so we don't fail tests
	for i := 0; i < processapi.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	id = ":ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)
}

func TestNamespaces(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	rootNs := namespace.GetCurrentNamespace()
	nsChecker := ec.NewNamespacesChecker().FromNamespaces(rootNs)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(tus.Conf().SelfBinary)).
		WithNs(nsChecker)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
	)

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestEventExitThreads(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testThreadsExit := testutils.RepoRootPath("contrib/tester-progs/threads-exit")

	// array of all pids we shuold receive in exet events
	tgids := make(map[int]bool)

	// running the workload 10 times to make the change we hit the race
	// window bigger and collect all tgids from testThreadsExit output
	for i := 0; i < 10; i++ {
		out, err := exec.Command(testThreadsExit).Output()
		if err != nil {
			t.Fatalf("Failed to execute test binary: %s\n", err)
		}

		tgid := 0
		if n, err := fmt.Sscanf(string(out[:]), "TGID %d", &tgid); n != 1 || err != nil {
			t.Fatalf("Failed to parse test binary output: %s\n", err)
		}
		tgids[tgid] = false
	}

	// check we got single exit event for each testThreadsExit
	// execution and no more
	nextCheck := func(event ec.Event, l *logrus.Logger) (bool, error) {
		switch ev := event.(type) {
		case *tetragon.ProcessExit:
			if ev.Process.Binary != testThreadsExit {
				return false, nil
			}
			// Make sure there's only single exit event with given pid
			pid := int(ev.Process.Pid.GetValue())
			assert.False(t, tgids[pid], "got extra exit event with pid %d", pid)
			tgids[pid] = true
			return false, nil
		default:
			return false, nil

		}
	}

	var seenAll bool

	finalCheck := func(l *logrus.Logger) error {
		// Make sure we saw all pids
		for pid, used := range tgids {
			if !used {
				t.Logf("Did not see exit event for pid %d", pid)

				// Cleanup the 'seen' tgids for one more events iteration
				for pid := range tgids {
					tgids[pid] = false
				}
				return fmt.Errorf("final check failed")
			}
		}
		seenAll = true
		return nil
	}

	checker_ := ec.FnEventChecker{
		NextCheckFn:  nextCheck,
		FinalCheckFn: finalCheck,
	}

	checker := testsensor.NewTestChecker(&checker_)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	assert.True(t, seenAll, "did not see all exit events")
}

func TestEventExecve(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop)).
		WithArguments(sm.Full("arg1 arg2 arg3"))

	execChecker := ec.NewProcessExecChecker("").WithProcess(procChecker)
	checker := ec.NewUnorderedEventChecker(execChecker)

	if err := exec.Command(testNop, "arg1", "arg2", "arg3").Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestEventExecveLongPath(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	// create dir portion of path
	baseDir := "/tmp/tetragon-execvetest/"
	testDir := baseDir

	dirNum := 14

	// kernels < v.5.16 won't trigger tracepoints for data bigger
	// than 2048 bytes, so making the path smaller for them
	if kernels.IsKernelVersionLessThan("5.16.0") {
		dirNum = 6
	}

	for d := 0; d < dirNum; d++ {
		for i := 0; i < 254; i++ {
			testDir = fmt.Sprintf("%s%c", testDir, 'a'+d)
		}
		testDir = testDir + "/"
	}

	// and add the file
	testBin := testDir
	for i := 0; i < 254; i++ {
		testBin = fmt.Sprintf("%s%c", testBin, 'a')
	}

	fmt.Printf("Path size: %d\n", len(testBin))
	fmt.Printf("Test dir: " + testDir + "\n")

	// create directory
	if err := os.MkdirAll(testDir, 0755); err != nil {
		if err := os.RemoveAll(baseDir); err != nil {
			t.Fatalf("Failed to remove test dir: %s", err)
		}
		if err := os.MkdirAll(testDir, 0755); err != nil {
			t.Logf("Failed to create test directory: %s\n", err)
		}
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(baseDir); err != nil {
			t.Fatalf("Failed to remove test dir: %s", err)
		}
	})

	// and link nop binary into the testBin
	if err := testutils.CopyFile(testBin, testNop, 0755); err != nil {
		t.Fatalf("Failed to copy binary: %s", err)
	}

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).
		WithArguments(sm.Full("arg1 arg2 arg3"))

	execChecker := ec.NewProcessExecChecker("").WithProcess(procChecker)
	checker := ec.NewUnorderedEventChecker(execChecker)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fmt.Printf("Exec: '%s arg1 arg2 arg3'\n", testBin)

	if err := exec.Command(testBin, "arg1", "arg2", "arg3").Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestEventExecveLongArgs(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	// prepare args
	testArg1 := "arg1_"
	for i := 0; i < 512; i++ {
		testArg1 = fmt.Sprintf("%s%c", testArg1, 'a')
	}

	testArg2 := "arg2_"
	for i := 0; i < 512; i++ {
		testArg2 = fmt.Sprintf("%s%c", testArg2, 'b')
	}

	testArg3 := "arg3_"
	for i := 0; i < 512; i++ {
		testArg3 = fmt.Sprintf("%s%c", testArg3, 'c')
	}

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop)).
		WithArguments(sm.Full(testArg1 + " " + testArg2 + " " + testArg3))

	execChecker := ec.NewProcessExecChecker("").WithProcess(procChecker)
	checker := ec.NewUnorderedEventChecker(execChecker)

	if err := exec.Command(testNop, testArg1, testArg2, testArg3).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestEventExecveLongPathLongArgs(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	// create dir portion of path
	baseDir := "/tmp/tetragon-execvetest/"
	testDir := baseDir

	dirNum := 14

	// kernels < v.5.16 won't trigger tracepoints for data bigger
	// than 2048 bytes, so making the path smaller for them
	if kernels.IsKernelVersionLessThan("5.16.0") {
		dirNum = 6
	}

	for d := 0; d < dirNum; d++ {
		for i := 0; i < 254; i++ {
			testDir = fmt.Sprintf("%s%c", testDir, 'a'+d)
		}
		testDir = testDir + "/"
	}

	// and add the file
	testBin := testDir
	for i := 0; i < 254; i++ {
		testBin = fmt.Sprintf("%s%c", testBin, 'a')
	}

	fmt.Printf("Path size: %d\n", len(testBin))
	fmt.Printf("Test dir: " + testDir + "\n")

	// create directory
	if err := os.MkdirAll(testDir, 0755); err != nil {
		if err := os.RemoveAll(baseDir); err != nil {
			t.Fatalf("Failed to remove test dir: %s", err)
		}
		if err := os.MkdirAll(testDir, 0755); err != nil {
			t.Logf("Failed to create test directory: %s\n", err)
		}
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(baseDir); err != nil {
			t.Fatalf("Failed to remove test dir: %s", err)
		}
	})

	// and link nop binary into the testBin
	if err := testutils.CopyFile(testBin, testNop, 0755); err != nil {
		t.Fatalf("Failed to copy binary: %s", err)
	}

	// prepare args
	testArg1 := "arg1_"
	for i := 0; i < 512; i++ {
		testArg1 = fmt.Sprintf("%s%c", testArg1, 'a')
	}

	testArg2 := "arg2_"
	for i := 0; i < 512; i++ {
		testArg2 = fmt.Sprintf("%s%c", testArg2, 'b')
	}

	testArg3 := "arg3_"
	for i := 0; i < 512; i++ {
		testArg3 = fmt.Sprintf("%s%c", testArg3, 'c')
	}

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).
		WithArguments(sm.Full(testArg1 + " " + testArg2 + " " + testArg3))

	execChecker := ec.NewProcessExecChecker("").WithProcess(procChecker)
	checker := ec.NewUnorderedEventChecker(execChecker)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fmt.Printf("Exec: '%s %s %s %s'\n", testBin, testArg1, testArg2, testArg3)

	if err := exec.Command(testBin, testArg1, testArg2, testArg3).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadInitialSensor(t *testing.T) {

	var sensorProgs = []tus.SensorProg{}
	var sensorMaps = []tus.SensorMap{}

	sensor := base.GetInitialSensor()

	option.Config.HubbleLib = tus.Conf().TetragonLib

	t.Logf("Loading sensor %v\n", sensor.Name)
	if err := sensor.Load(bpf.MapPrefixPath(), bpf.MapPrefixPath()); err != nil {
		t.Fatalf("sensor.Load failed: %v\n", err)
	}

	tus.CheckSensorLoad([]*sensors.Sensor{sensor}, sensorMaps, sensorProgs, t)

	sensor.Unload()
}

func TestDocker(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	serverDockerID := observertesthelper.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:v1.6.0", "-nvlp", "8081", "-s", "0.0.0.0")
	time.Sleep(1 * time.Second)

	// Tetragon sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := sm.Prefix(serverDockerID[:24])

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(tus.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-nvlp 8081 -s 0.0.0.0")).
		WithCwd(sm.Full("/")).
		WithUid(0).
		WithDocker(fgsServerID)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("client").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("server").
			WithProcess(ncSrvChecker),
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestUpdateStatsMap(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Close()
	})

	lookup := func() int64 {
		var sum int64
		var v []int64

		if err := m.Lookup(uint32(0), &v); err != nil {
			t.Fatalf("lookup error: %s", err)
		}

		for _, val := range v {
			sum += val
		}
		return sum
	}

	before := lookup()
	if before != 0 {
		t.Fatalf("wrong initial lookup value '%d'", before)
	}

	if err := sensors.UpdateStatsMap(m, 100); err != nil {
		t.Fatalf("UpdateMap failed: %s", err)
	}

	after := lookup()
	if after != 100 {
		t.Fatalf("wrong final lookup value '%d'", after)
	}
}

func TestExecPerfring(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())

	ops := func() {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Logf("command failed: %s", err)
		}
	}
	events := perfring.RunTestEvents(t, ctx, ops)
	for _, ev := range events {
		if exec, ok := ev.(*grpcexec.MsgExecveEventUnix); ok {
			if exec.Process.Filename == "/bin/true" {
				return
			}
		}
	}
	t.Fatalf("failed to find exec event")
}

func TestExecParse(t *testing.T) {
	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observer.InitDataCache: %s", err)
	}

	exec := processapi.MsgExec{
		Size: processapi.MSG_SIZEOF_EXECVE,
	}

	filename := []byte("/bin/krava")
	cwd := []byte("/home/krava")

	// Following tests prepare reader with MsgExec event plus additional data
	// that follows it - filename, arguments, cwd
	//
	// The filename could be in form of data event or string. The arguments
	// data is optional and can be only in form of data event. This setup is
	// reflected in MsgExec::Flags.
	//
	// Based on the MsgExec::Flags the execParse function parses out MsgProcess
	// object, and we retrieve and check its Args value with ArgsDecoder
	// function which is used in GetProcess.

	var err error

	{
		// - filename (string)
		// - no args
		// - cwd (string)

		exec.Flags = 0
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + len(cwd) + 1)

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, []byte{0})
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, empty, err := execParse(reader)
		assert.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, string(cwd), process.Args)
		assert.Equal(t, empty, false)

		decArgs, decCwd := proc.ArgsDecoder(process.Args, process.Flags)
		assert.Equal(t, "", decArgs)
		assert.Equal(t, string(cwd), decCwd)
	}

	observer.DataPurge()

	{
		// - filename (data event)
		// - no args
		// - cwd (string)

		id := dataapi.DataEventId{Pid: 1, Time: 1}
		desc := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(filename[:])), Id: id}
		err = observer.DataAdd(id, filename)
		assert.NoError(t, err)

		exec.Flags = api.EventDataFilename
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + binary.Size(desc) + len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, desc)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, empty, err := execParse(reader)
		assert.NoError(t, err)

		// execParse check
		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, string(cwd), process.Args)
		assert.Equal(t, empty, false)

		// ArgsDecoder check
		decArgs, decCwd := proc.ArgsDecoder(process.Args, process.Flags)
		assert.Equal(t, "", decArgs)
		assert.Equal(t, string(cwd), decCwd)
	}

	observer.DataPurge()

	{
		// - filename (string)
		// - args (data event)
		// - cwd (string)

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2', 0)

		id := dataapi.DataEventId{Pid: 1, Time: 2}
		desc := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(args[:])), Id: id}
		err = observer.DataAdd(id, args)
		assert.NoError(t, err)

		exec.Flags = api.EventDataArgs
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + binary.Size(desc) + len(cwd) + 1)

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, []byte{0})
		binary.Write(&buf, binary.LittleEndian, desc)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, empty, err := execParse(reader)
		assert.NoError(t, err)

		// execParse check
		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, string(args)+string(cwd), process.Args)
		assert.Equal(t, empty, false)

		// ArgsDecoder check
		decArgs, decCwd := proc.ArgsDecoder(process.Args, process.Flags)
		assert.Equal(t, "arg1 arg2", decArgs)
		assert.Equal(t, string(cwd), decCwd)
	}

	observer.DataPurge()

	{
		// - filename (data event)
		// - args (data event)
		// - cwd (string)

		id1 := dataapi.DataEventId{Pid: 1, Time: 1}
		desc1 := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(filename[:])), Id: id1}
		err = observer.DataAdd(id1, filename)
		assert.NoError(t, err)

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2', 0)

		id2 := dataapi.DataEventId{Pid: 1, Time: 2}
		desc2 := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(args[:])), Id: id2}
		err = observer.DataAdd(id2, args)
		assert.NoError(t, err)

		exec.Flags = api.EventDataFilename | api.EventDataArgs
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + binary.Size(desc1) + binary.Size(desc2) + len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, desc1)
		binary.Write(&buf, binary.LittleEndian, desc2)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, empty, err := execParse(reader)
		assert.NoError(t, err)

		// execParse check
		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, string(args)+string(cwd), process.Args)
		assert.Equal(t, empty, false)

		// ArgsDecoder check
		decArgs, decCwd := proc.ArgsDecoder(process.Args, process.Flags)
		assert.Equal(t, "arg1 arg2", decArgs)
		assert.Equal(t, string(cwd), decCwd)
	}

	{
		// - filename (non-utf8)
		// - args (data event, non-utf8)
		// - cwd (string)

		var args []byte
		args = append(args, '\xc3', '\x28', 0, 'a', 'r', 'g', '2', 0)
		filename := []byte{'p', 'i', 'z', 'z', 'a', '-', '\xc3', '\x28'}
		cwd := []byte{'/', 'h', 'o', 'm', 'e', '/', '\xc3', '\x28'}

		id := dataapi.DataEventId{Pid: 1, Time: 2}
		desc := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(args[:])), Id: id}
		err = observer.DataAdd(id, args)
		assert.NoError(t, err)

		exec.Flags = api.EventDataArgs
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + binary.Size(desc) + len(cwd) + 1)

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, []byte{0})
		binary.Write(&buf, binary.LittleEndian, desc)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, empty, err := execParse(reader)
		assert.NoError(t, err)

		// execParse check
		assert.Equal(t, strutils.UTF8FromBPFBytes(filename), process.Filename)
		assert.Equal(t, strutils.UTF8FromBPFBytes(args)+strutils.UTF8FromBPFBytes(cwd), process.Args)
		assert.Equal(t, empty, false)

		// ArgsDecoder check
		decArgs, decCwd := proc.ArgsDecoder(process.Args, process.Flags)
		assert.Equal(t, "�( arg2", decArgs)
		assert.Equal(t, strutils.UTF8FromBPFBytes(cwd), decCwd)
	}
	observer.DataPurge()
}

// Tests process.process_credentials
func TestExecProcessCredentials(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	oldGid := syscall.Getgid()
	gid := uint32(1879048193)
	if err := syscall.Setegid(int(gid)); err != nil {
		t.Fatalf("setegid(%d) error: %s", gid, err)
	}
	t.Cleanup(func() {
		// Restores all gids since we retain capabilities
		if err = syscall.Setgid(oldGid); err != nil {
			t.Fatalf("Failed to restore gid to %d :  %s\n", oldGid, err)
		}
	})

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	creds := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(0).WithEgid(0).WithSgid(0).WithFsgid(0)

	gidCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(0).WithEgid(gid).WithSgid(gid).WithFsgid(gid)

	procExecChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop)).WithProcessCredentials(creds).WithBinaryProperties(nil)

	procGidExecChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop)).WithProcessCredentials(gidCreds).WithBinaryProperties(nil)

	execChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecChecker)
	execGidChecker := ec.NewProcessExecChecker("exec").WithProcess(procGidExecChecker)
	exitChecker := ec.NewProcessExitChecker("exit").WithProcess(procExecChecker)
	exitGidChecker := ec.NewProcessExitChecker("exit").WithProcess(procGidExecChecker)

	checker := ec.NewUnorderedEventChecker(execChecker, execGidChecker, exitChecker, exitGidChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// Test ensures that running as fully privileged root and executing a setuid or
// setgid to root does not generate a binary_properties setuid field nor privs_changed fields.
func TestExecProcessCredentialsSuidRootNoPrivsChange(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}

	testBin := testutils.RepoRootPath("contrib/tester-progs/nop")
	// We should be able to create suid on local mount point
	testSuid := testutils.RepoRootPath("contrib/tester-progs/suidnop")
	if err := testutils.CopyFile(testSuid, testBin, 0754|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatalf("Failed to copy binary: %s", err)
	}
	t.Cleanup(func() {
		err := os.Remove(testSuid)
		if err != nil {
			t.Logf("Error failed to cleanup '%s'", testSuid)
		}
	})

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	noCredsChange := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(0).WithEgid(0).WithSgid(0).WithFsgid((0))
	procExecNoPrivilegesChanged := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).WithProcessCredentials(noCredsChange).WithBinaryProperties(nil)
	execNoPrivilegesChangedChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecNoPrivilegesChanged)
	if err := exec.Command(testBin).Run(); err != nil {
		t.Fatalf("Failed to execute '%s' binary: %s\n", testBin, err)
	}
	/* Executing a setuid and setgid to root but we are already running as root
	 * so no privilege change should be detected, same filters as above apply.
	 */
	if err := os.Chown(testSuid, 0, 0); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}
	if err := os.Chmod(testSuid, 0754|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}
	procExecSetuidRootNoPrivilegesChanged := ec.NewProcessChecker().
		WithBinary(sm.Full(testSuid)).WithProcessCredentials(noCredsChange).WithBinaryProperties(nil)
	execSetuidRootNoPrivilegesChangedChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecSetuidRootNoPrivilegesChanged)
	if err := exec.Command(testSuid).Run(); err != nil {
		t.Fatalf("Failed to execute '%s' binary: %s\n", testSuid, err)
	}

	checker := ec.NewUnorderedEventChecker(execNoPrivilegesChangedChecker, execSetuidRootNoPrivilegesChangedChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// Test running with different combinations of setgid bit set
//  1. setgid() systemcall to arbitrary gid value then exec binary to
//     assert credentials did not change.
//  2. executes a set-group-ID to root binary asserting that we detect
//     the setgid bit set + the privileges changed due to the setgid bit
//     being set to root group.
//  3. executes a set-group-ID to non root, it is set to arbitrary value
//     to assert that binary execution detects the setgid bit but we do
//     not report as a privilege changed execution as the target group
//     is not root.
func TestExecProcessCredentialsSetgidChanges(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}

	testBin := testutils.RepoRootPath("contrib/tester-progs/nop")
	// We should be able to create suid on local mount point
	testSuid := testutils.RepoRootPath("contrib/tester-progs/suidnop")
	if err := testutils.CopyFile(testSuid, testBin, 0754|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatalf("Failed to copy binary: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	oldGid := syscall.Getgid()
	/* Executing a setgid to root with current gid as normal not root */
	gid := 1879048188
	if err := syscall.Setgid(gid); err != nil {
		t.Fatalf("setgid(%d) error: %s", gid, err)
	}
	t.Cleanup(func() {
		// Restore old gid
		if err = syscall.Setgid(oldGid); err != nil {
			t.Fatalf("Failed to restore gid to %d :  %s\n", oldGid, err)
		}
		err := os.Remove(testSuid)
		if err != nil {
			t.Logf("Error failed to cleanup '%s'", testSuid)
		}
	})

	noGidCredsChanged := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(uint32(gid)).WithEgid(uint32(gid)).WithSgid(uint32(gid)).WithFsgid(uint32(gid))
	procExecNoGidCredsChangedChecker := ec.NewProcessChecker().WithUid(uint32(0)).
		WithBinary(sm.Full(testBin)).WithProcessCredentials(noGidCredsChanged).WithBinaryProperties(nil)
	execNoGidsCredsChangedChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecNoGidCredsChangedChecker)
	if err := exec.Command(testBin).Run(); err != nil {
		t.Fatalf("Failed to execute '%s' binary: %s\n", testBin, err)
	}

	if err := os.Chown(testSuid, 0, 0); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}
	if err := os.Chmod(testSuid, 0754|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}
	/* Setgid to 0 */
	privsChangedRaiseSetgid := ec.NewProcessPrivilegesChangedListMatcher().WithOperator(lc.Ordered).
		WithValues(ec.NewProcessPrivilegesChangedChecker(tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_SETGID))
	bpSetgidRoot := ec.NewBinaryPropertiesChecker().
		WithSetgid(0).WithPrivilegesChanged(privsChangedRaiseSetgid)
	setgidRootCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(uint32(gid)).WithEgid(0).WithSgid(0).WithFsgid(0)
	procExecSetgidRootChecker := ec.NewProcessChecker().WithUid(uint32(0)).
		WithBinary(sm.Full(testSuid)).WithProcessCredentials(setgidRootCreds).WithBinaryProperties(bpSetgidRoot)
	execSetgidRootChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecSetgidRootChecker)
	procExitSetgidRootChecker := ec.NewProcessChecker().WithUid(uint32(0)).
		WithBinary(sm.Full(testSuid)).WithProcessCredentials(setgidRootCreds).WithBinaryProperties(nil)
	exitSetgidRootChecker := ec.NewProcessExitChecker("exit").WithProcess(procExitSetgidRootChecker)

	if err := exec.Command(testSuid).Run(); err != nil {
		t.Fatalf("Failed to execute '%s' suid binary: %s\n", testSuid, err)
	}

	/* Setuid to gid and Setgid to gid both are not root */
	/* First restore gid to root */
	if err := syscall.Setgid(0); err != nil {
		t.Fatalf("setegid(%d) error: %s", gid, err)
	}

	if err := os.Chown(testSuid, gid, gid); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}

	if err := os.Chmod(testSuid, 0754|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}

	bpSetgidNoRoot := ec.NewBinaryPropertiesChecker().
		WithSetuid(uint32(gid)).WithSetgid(uint32(gid)).WithPrivilegesChanged(nil)
	setgidNonRootCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(uint32(gid)).WithSuid(uint32(gid)).WithFsuid(uint32(gid)).
		WithGid(0).WithEgid(uint32(gid)).WithSgid(uint32(gid)).WithFsgid(uint32(gid))
	procExecSetgidNoRootChecker := ec.NewProcessChecker().WithUid(uint32(0)).
		WithBinary(sm.Full(testSuid)).WithProcessCredentials(setgidNonRootCreds).WithBinaryProperties(bpSetgidNoRoot)
	execSetgidNoRootChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecSetgidNoRootChecker)
	procExitSetgidNoRootChecker := ec.NewProcessChecker().WithUid(uint32(0)).
		WithBinary(sm.Full(testSuid)).WithProcessCredentials(setgidNonRootCreds).WithBinaryProperties(nil)
	exitSetgidNoRootChecker := ec.NewProcessExitChecker("exit").WithProcess(procExitSetgidNoRootChecker)

	if err := exec.Command(testSuid).Run(); err != nil {
		t.Fatalf("Failed to execute secound round suid '%s' binary: %s\n", testSuid, err)
	}

	checker := ec.NewUnorderedEventChecker(execNoGidsCredsChangedChecker, execSetgidRootChecker, exitSetgidRootChecker, execSetgidNoRootChecker, exitSetgidNoRootChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// Test running with different combinations of setuid bit set
//  1. executes a set-user-ID to non root, it is set to arbitrary value
//     to assert that binary execution detects the setuid bit but we do
//     not report as a privilege changed execution as the target user
//     is not root.
//  2. executes a set-user-ID to root binary asserting that we detect
//     the setuid bit set + the privileges changed due to the setuid bit
//     being set to root.
func TestExecProcessCredentialsSetuidChanges(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}

	testBin := testutils.RepoRootPath("contrib/tester-progs/nop")
	// The drop-privileges is a helper binary that drops privileges so we do not
	// drop it inside this test which will break the test framework.
	testDrop := testutils.RepoRootPath("contrib/tester-progs/drop-privileges")
	testSu, err := exec.LookPath("su")
	if err != nil {
		t.Skip("Could not find 'su' binary skipping")
	}
	// We should be able to create suid on local mount point
	// This binary will have setuid set to non root.
	testSuid := testutils.RepoRootPath("contrib/tester-progs/suidnop")
	if err := testutils.CopyFile(testSuid, testBin, 0755|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatalf("Failed to copy binary: %s", err)
	}
	t.Cleanup(func() {
		err := os.Remove(testSuid)
		if err != nil {
			t.Logf("Error failed to cleanup '%s'", testSuid)
		}
	})

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	gid := 1879048188
	if err := os.Chown(testSuid, gid, gid); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}

	if err := os.Chmod(testSuid, 0755|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatalf("Chown() on '%s' binary error: %s\n", testSuid, err)
	}

	bpSetuidNoRoot := ec.NewBinaryPropertiesChecker().
		WithSetuid(uint32(gid)).WithSetgid(uint32(gid)).WithPrivilegesChanged(nil)
	setuidNonRootCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(uint32(gid)).WithSuid(uint32(gid)).WithFsuid(uint32(gid)).
		WithGid(0).WithEgid(uint32(gid)).WithSgid(uint32(gid)).WithFsgid(uint32(gid))
	procExecSetuidNoRootChecker := ec.NewProcessChecker().WithUid(uint32(0)).
		WithBinary(sm.Full(testSuid)).WithProcessCredentials(setuidNonRootCreds).WithBinaryProperties(bpSetuidNoRoot)
	execSetuidNoRootChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecSetuidNoRootChecker)
	procExitSetuidNoRootChecker := ec.NewProcessChecker().WithUid(uint32(0)).
		WithBinary(sm.Full(testSuid)).WithProcessCredentials(setuidNonRootCreds).WithBinaryProperties(nil)
	exitSetuidNoRootChecker := ec.NewProcessExitChecker("exit").WithProcess(procExitSetuidNoRootChecker)

	if err := exec.Command(testSuid).Run(); err != nil {
		t.Fatalf("Failed to execute suid '%s' binary: %s\n", testSuid, err)
	}

	privsChangedRaiseSetuid := ec.NewProcessPrivilegesChangedListMatcher().WithOperator(lc.Ordered).
		WithValues(ec.NewProcessPrivilegesChangedChecker(tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_SETUID))
	bpSetuidRoot := ec.NewBinaryPropertiesChecker().
		WithSetuid(0).WithPrivilegesChanged(privsChangedRaiseSetuid)
	setuidRootCreds := ec.NewProcessCredentialsChecker().
		WithUid(uint32(gid)).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(uint32(gid)).WithEgid(uint32(gid)).WithSgid(uint32(gid)).WithFsgid(uint32(gid))
	procExecSetuidRootChecker := ec.NewProcessChecker().WithUid(uint32(gid)).
		WithBinary(sm.Full(testSu)).WithProcessCredentials(setuidRootCreds).WithBinaryProperties(bpSetuidRoot)
	execSetuidRootChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecSetuidRootChecker)
	procExitSetuidRootChecker := ec.NewProcessChecker().WithUid(uint32(gid)).
		WithBinary(sm.Full(testSu)).WithProcessCredentials(setuidRootCreds).WithBinaryProperties(nil)
	exitSetuidRootChecker := ec.NewProcessExitChecker("exit").WithProcess(procExitSetuidRootChecker)

	// We use the testDrop to drop uid so we don't break the test framework by
	// chaning the uid here. The testDrop binary will execute su binary as we are sure
	// its path allows to exec into directory but also execute the su binary.
	// The result is based on the su binary being detected as a privilege_changed execution.
	testCmd := exec.CommandContext(ctx, testDrop, testSu, "--help")
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	checker := ec.NewUnorderedEventChecker(execSetuidNoRootChecker, exitSetuidNoRootChecker, execSetuidRootChecker, exitSetuidRootChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// Detect execution of binaries with file capability sets
func TestExecProcessCredentialsFileCapChanges(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}

	// The drop-privileges is a helper binary that drops privileges so we do not
	// drop it inside this test which will break the test framework.
	testDrop := testutils.RepoRootPath("contrib/tester-progs/drop-privileges")
	testPing, err := exec.LookPath("ping")
	if err != nil {
		t.Skipf("Skipping test could not find 'ping' binary: %v", err)
	}

	xattrs := make([]byte, 0)
	ret, err := unix.Getxattr(testPing, "security.capability", xattrs)
	if err != nil {
		t.Skipf("Skipping test could 'security.capability' xattr of binary '%s' error: %v", testPing, err)
	}
	if ret == 0 {
		t.Skipf("Skipping test 'security.capability' xattr is not set on binary '%s'", testPing)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	gid := 1879048188
	privsChangedRaiseFscaps := ec.NewProcessPrivilegesChangedListMatcher().WithOperator(lc.Ordered).
		WithValues(ec.NewProcessPrivilegesChangedChecker(tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_CAP))
	bp := ec.NewBinaryPropertiesChecker().WithPrivilegesChanged(privsChangedRaiseFscaps)
	noRootCreds := ec.NewProcessCredentialsChecker().
		WithUid(uint32(gid)).WithEuid(uint32(gid)).WithSuid(uint32(gid)).WithFsuid(uint32(gid)).
		WithGid(uint32(gid)).WithEgid(uint32(gid)).WithSgid(uint32(gid)).WithFsgid(uint32(gid))
	procExecFsCapsChecker := ec.NewProcessChecker().WithUid(uint32(gid)).
		WithBinary(sm.Full(testPing)).WithProcessCredentials(noRootCreds).WithBinaryProperties(bp)
	execChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecFsCapsChecker)
	procExitFsCapsChecker := ec.NewProcessChecker().WithUid(uint32(gid)).
		WithBinary(sm.Full(testPing)).WithProcessCredentials(noRootCreds).WithBinaryProperties(nil)
	exitChecker := ec.NewProcessExitChecker("exit").WithProcess(procExitFsCapsChecker)

	// We use the testDrop to drop uid so we don't break the test framework by
	// changing the uid here. The testDrop binary will execute ping binary as we are sure
	// its path allows to exec into directory but also execute the ping binary.
	// The result is based on the ping binary being detected as a privilege_changed execution.
	testCmd := exec.CommandContext(ctx, testDrop, testPing, "-V")
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	checker := ec.NewUnorderedEventChecker(execChecker, exitChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
