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
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	proc "github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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

	// and copy nop binary into the testBin
	fmt.Printf("Copy: /usr/bin/cp -f " + testNop + " " + testBin + "\n")

	if err := exec.Command("/usr/bin/cp", "-f", testNop, testBin).Run(); err != nil {
		t.Fatalf("Failed to copy binary: %s", err)
	}

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).
		WithArguments(sm.Full("arg1 arg2 arg3"))

	execChecker := ec.NewProcessExecChecker("").WithProcess(procChecker)
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

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	execChecker := ec.NewProcessExecChecker("").WithProcess(procChecker)
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

	var sensorProgs = []tus.SensorProg{}
	var sensorMaps = []tus.SensorMap{}

	sensor := base.GetInitialSensor()

	option.Config.HubbleLib = tus.Conf().TetragonLib

	t.Logf("Loading sensor %v\n", sensor.Name)
	if err := sensor.Load(bpf.MapPrefixPath(), bpf.MapPrefixPath(), ""); err != nil {
		t.Fatalf("sensor.Load failed: %v\n", err)
	}

	tus.CheckSensorLoad([]*sensors.Sensor{sensor}, sensorMaps, sensorProgs, t)

	sensors.UnloadAll()
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
	serverDockerID := observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:v1.6.0", "-nvlp", "8081", "-s", "0.0.0.0")
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
		t.Fatalf("observer.InitDataCache: %s", err)
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
		desc := dataapi.DataEventDesc{Error: 0, Leftover: 0, Id: id}
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
		desc := dataapi.DataEventDesc{Error: 0, Leftover: 0, Id: id}
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
		desc1 := dataapi.DataEventDesc{Error: 0, Leftover: 0, Id: id1}
		err = observer.DataAdd(id1, filename)
		assert.NoError(t, err)

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2', 0)

		id2 := dataapi.DataEventId{Pid: 1, Time: 2}
		desc2 := dataapi.DataEventDesc{Error: 0, Leftover: 0, Id: id2}
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

	observer.DataPurge()
}
