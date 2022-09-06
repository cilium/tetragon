// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	api "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorExec")
	os.Exit(ec)
}

func Test_msgToExecveKubeUnix(t *testing.T) {
	event := api.MsgExecveEvent{}
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
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	// Not valid
	id = "ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)

	// Empty event so we don't fail tests
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
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
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
	)

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestEventExecve(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.ContribPath("tester-progs/nop")

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop)).
		WithArguments(sm.Full("arg1 arg2 arg3"))

	execChecker := ec.NewProcessExecChecker().WithProcess(procChecker)
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

	if !kernels.EnableLargeProgs() {
		t.Skip()
	}

	testNop := testutils.ContribPath("tester-progs/nop")

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

	// and copy nop binary into the testBin
	fmt.Printf("Copy: /usr/bin/cp -f " + testNop + " " + testBin + "\n")

	if err := exec.Command("/usr/bin/cp", "-f", testNop, testBin).Run(); err != nil {
		t.Fatalf("Failed to copy binary: %s", err)
	}

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).
		WithArguments(sm.Full("arg1 arg2 arg3"))

	execChecker := ec.NewProcessExecChecker().WithProcess(procChecker)
	checker := ec.NewUnorderedEventChecker(execChecker)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	if !kernels.EnableLargeProgs() {
		t.Skip()
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.ContribPath("tester-progs/nop")

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

	execChecker := ec.NewProcessExecChecker().WithProcess(procChecker)
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

	if !kernels.EnableLargeProgs() {
		t.Skip()
	}

	testNop := testutils.ContribPath("tester-progs/nop")

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

	// and copy nop binary into the testBin
	fmt.Printf("Copy: /usr/bin/cp -f " + testNop + " " + testBin + "\n")

	if err := exec.Command("/usr/bin/cp", "-f", testNop, testBin).Run(); err != nil {
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

	execChecker := ec.NewProcessExecChecker().WithProcess(procChecker)
	checker := ec.NewUnorderedEventChecker(execChecker)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fmt.Printf("Exec: '%s %s %s %s'\n", testBin, testArg1, testArg2, testArg3)

	if err := exec.Command(testBin, testArg1, testArg2, testArg3).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadInitialSensor(t *testing.T) {

	var sensorProgs = []tus.SensorProg{
		0: tus.SensorProg{Name: "event_execve", Type: ebpf.TracePoint},
		1: tus.SensorProg{Name: "event_exit", Type: ebpf.TracePoint},
		2: tus.SensorProg{Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
		// all programs
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2}},
		tus.SensorMap{Name: "execve_map_stats", Progs: []uint{0, 1, 2}},
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2}},

		// event_execve
		tus.SensorMap{Name: "names_map", Progs: []uint{0}},

		// event_wake_up_new_task
		tus.SensorMap{Name: "execve_val", Progs: []uint{2}},
	}

	sensor := base.GetInitialSensor()

	option.Config.HubbleLib = tus.Conf().TetragonLib

	t.Logf("Loading sensor %v\n", sensor.Name)
	if err := sensor.Load(context.TODO(), bpf.MapPrefixPath(), bpf.MapPrefixPath(), ""); err != nil {
		t.Fatalf("sensor.Load failed: %v\n", err)
	}

	tus.CheckSensorLoad([]*sensors.Sensor{sensor}, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)
}

func TestDocker(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	serverDockerID := observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081", "-s", "0.0.0.0")
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
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncSrvChecker),
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
