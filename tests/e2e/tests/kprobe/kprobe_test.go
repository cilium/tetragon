package kprobe_test

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/tests/e2e/helpers/grpc"
	"github.com/sirupsen/logrus"
	"testing"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// This holds our test environment which we get from calling runners.NewRunner().Setup()
var runner *runners.Runner

// The namespace where we want to spawn our pods
const namespace = "kprobe-test"

var (
	// Basic Tetragon parameters
	TetragonNamespace  = "kube-system"
	TetragonAppNameKey = "app.kubernetes.io/name"
	TetragonAppNameVal = "tetragon"
	TetragonContainer  = "tetragon"
	TetragonCLI        = "tetra"
	readCmd            = "cat"
	writeCmd           = "/usr/bin/echo"
)

func TestMain(m *testing.M) {
	runner = runners.NewRunner().Init()

	// Here we ensure our test namespace doesn't already exist then create it.
	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.DeleteNamespace(namespace, true)(ctx, c)

		ctx, err := helpers.CreateNamespace(namespace, true)(ctx, c)
		if err != nil {
			return ctx, fmt.Errorf("failed to create namespace: %w", err)
		}

		return ctx, nil
	})

	// Run the tests using the test runner.
	runner.Run(m)
}

func TestKprobeTracingPolicy(t *testing.T) {
	runner.SetupExport(t)

	// Create an curl event checker with a limit or 10 events or 30 seconds, whichever comes first
	checker := kprobeChecker().WithEventLimit(20).WithTimeLimit(30 * time.Second)

	// Define test features here. These can be used to perform actions like:
	// - Spawning an event checker and running checks
	// - Modifying resources in the cluster
	// - etc.

	// This starts curlChecker and uses it to run event checks.
	runEventChecker := features.New("Run Event Checks").
		Assess("Run Event Checks",
			checker.CheckWithFilters(
				// allow list
				30*time.Second,
				[]*tetragon.Filter{{
					EventSet:  []tetragon.EventType{tetragon.EventType_PROCESS_KPROBE},
					Namespace: []string{namespace},
				}},
				// deny list
				[]*tetragon.Filter{},
			)).Feature()

	// This feature waits for curlChecker to start then runs a custom workload.
	runWorkload := features.New("Run kprobe test").
		Assess("Install policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString(namespace, kprobeReadWritePolicy, false)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to install policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for policy", func(ctx context.Context, _ *testing.T, _ *envconf.Config) context.Context {
			if err := grpc.WaitForTracingPolicy(ctx, "sys-write"); err != nil {
				klog.ErrorS(err, "failed to wait for policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for Checker", checker.Wait(30*time.Second)).
		Assess("Start pods", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			var err error
			for _, pod := range []string{ubuntuReadPod, ubuntuWritePod} {
				ctx, err = helpers.LoadCRDString(namespace, pod, true)(ctx, c)
				if err != nil {
					klog.ErrorS(err, "failed to load pod")
					t.Fail()
				}

			}
			return ctx
		}).
		Assess("Uninstall policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.UnloadCRDString(namespace, kprobeReadWritePolicy, true)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to uninstall policy")
				t.Fail()
			}
			return ctx
		}).Feature()

	runner.TestInParallel(t, runEventChecker, runWorkload)
}

const kprobeReadWritePolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "sys-read-write"
spec:
  kprobes:
  - call: "sys_write"
    syscall: true
  - call: "sys_read"
    syscall: true
`

var ubuntuWritePod = fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: ubuntu-write
  name: ubuntu-write
spec:
  containers:
  - args:
    - %s
    - hello
    image: ubuntu
    name: ubuntu-write
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
`, writeCmd)

var ubuntuReadPod = fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: ubuntu-read
  name: ubuntu-read
spec:
  containers:
  - args:
    - %s
    - /etc/hostname
    image: ubuntu
    name: ubuntu-read
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
`, readCmd)

func kprobeChecker() *checker.RPCChecker {
	return checker.NewRPCChecker(&kprobeCheker{}, "kprobe-checker")
}

type kprobeCheker struct {
	matches int
}

func (k *kprobeCheker) NextEventCheck(event ec.Event, _ *logrus.Logger) (bool, error) {
	// ignore other events
	ev, ok := event.(*tetragon.ProcessKprobe)
	if !ok {
		return false, errors.New("not a process kprobe")
	}

	if ev.GetFunctionName() == "__x64_sys_write" && ev.GetProcess().GetBinary() == writeCmd {
		k.matches++
	}
	if ev.GetFunctionName() == "__x64_sys_read" && ev.GetProcess().GetBinary() == readCmd {
		k.matches++
	}

	return false, nil
}

func (k *kprobeCheker) FinalCheck(logger *logrus.Logger) error {
	if k.matches >= 2 {
		return nil
	}
	return fmt.Errorf("kprobe checker failed, had %d matches", k.matches)
}
