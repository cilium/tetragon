// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/matchers/stringmatcher"
	api "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/stretchr/testify/assert"
)

var (
	selfBinary   string
	tetragonLib  string
	cmdWaitTime  time.Duration
	verboseLevel int
)

func init() {
	flag.StringVar(&tetragonLib, "bpf-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an TETRAGON_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for tetragon to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")

	bpf.SetMapPrefix("testObserver")
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
}

func Test_msgToExecveUnix(t *testing.T) {
	event := api.MsgExecveEvent{}
	idLength := procevents.BpfContainerIdLength

	// Minikube has "docker-" prefix.
	prefix := "docker-"
	minikubeID := prefix + "9e123a99b140a6ea4a8d15040ca2c8ee2d5ee9605e81d66ae4e3e29c3f0ef220.scope"
	copy(event.Kube.Docker[:], minikubeID)
	result := msgToExecveUnix(&event)
	assert.Equal(t, strings.Split(minikubeID, "-")[1][:idLength], result.Kube.Docker)
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event)
	assert.Empty(t, result.Kube.Docker)

	// GKE doesn't.
	gkeID := "82836ef3675020258bee5075ace6264b3bc5300e20c975543cbc984bea59638f"
	copy(event.Kube.Docker[:], gkeID)
	result = msgToExecveUnix(&event)
	assert.Equal(t, gkeID[:idLength], result.Kube.Docker)
	assert.Equal(t, idLength, len(result.Kube.Docker))
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event)
	assert.Empty(t, result.Kube.Docker)

	id := "kubepods-burstable-pod29349498_197c_4919_b13f_9a928e7d001b.slice:cri-containerd:0ca2b3cd20e5f55a2bbe8d4aa3f811cf7963b40f0542ad147054b0fcb60fc400"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event)
	assert.Equal(t, id[80:80+idLength], result.Kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:idLength], result.Kube.Docker)
	assert.Equal(t, idLength, len(result.Kube.Docker))

	id = "kubepods-besteffort-pod13cb8437-00ed-40e4-99d8-e17193a58086.slice:cri-containerd:a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event)
	assert.Equal(t, id[81:81+idLength], result.Kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:idLength], result.Kube.Docker)
	assert.Equal(t, idLength, len(result.Kube.Docker))

	id = "cri-containerd-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event)
	assert.Equal(t, strings.Split(id, "-")[2][:idLength], result.Kube.Docker)
	assert.Equal(t, idLength, len(result.Kube.Docker))

	id = "libpod-01f3c60cfaadbb51e4d5947dd2ef0480d53551cbcee8f3ada8c3723b2bf03bf4"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event)
	assert.Equal(t, strings.Split(id, "-")[1][:idLength], result.Kube.Docker)
	assert.Equal(t, idLength, len(result.Kube.Docker))

	id = ":a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event)
	assert.Equal(t, strings.Split(id, ":")[1][:idLength], result.Kube.Docker)
	assert.Equal(t, idLength, len(result.Kube.Docker))

	// Empty event so we don't fail tests
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	// Not valid
	id = "ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event)
	assert.Empty(t, result.Kube.Docker)

	// Empty event so we don't fail tests
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	id = ":ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event)
	assert.Empty(t, result.Kube.Docker)
}

func TestNamespaces(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	rootNs := namespace.GetCurrentNamespace()
	nsChecker := ec.NewNamespacesChecker().FromNamespaces(rootNs)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(selfBinary)).
		WithNs(nsChecker)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
	)

	obs, err := observer.GetDefaultObserver(t, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
