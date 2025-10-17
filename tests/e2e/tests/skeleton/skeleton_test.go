// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// This package contains a simple test skeleton that can be copied, pasted, and modified
// to create new Tetragon e2e tests.
package skeleton_test

import (
	"context"
	_ "embed"
	"fmt"
	"testing"
	"time"

	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/tests/e2e/metricschecker"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

// This holds our test environment which we get from calling runners.NewRunner().Setup()
var runner *runners.Runner

// The namespace where we want to spawn our pods
const namespace = "skeleton"

// Every e2e test needs a TestMain with the two lines below. The runner supports
// customization options that can be used to override its setup behaviour, but in most
// cases the defaults will be enough combined with command line flags.
//
// See tests/e2e/flags/flags.go for a detailed overview of what Tetragon-specific command
// line flags can be used.
func TestMain(m *testing.M) {
	// Set up the tests. In a default configuration, this does the following:
	//
	// 1. At the beginning of every test, check to see whether we have a kubeconfig file
	//    (specified at the command line with -kubeconfig). If not, create a temporary
	//    kind cluster to run the tests.
	//
	// 2. After the cluster is configured and running, query the minimum kernel versions
	//    supported by all nodes and set this as a variable in the test context.
	//
	// 3. Register a hook at the start of every test that installs Tetragon into the
	//    cluster with some default options.
	//
	// 4. Register a hook at the start of every test that port forwards Tetragon metrics
	//    and gRPC ports for all pods. These port forwards are registered in the test
	//    context for later retrieval.
	//
	// 5. Register a hook at the end of every test that dumps information about the
	//    cluster and running event checkers. This information is only dumped if the test
	//    fails or if -tetragon.keep-export=true is set on the command line.
	//
	runner = runners.NewRunner().Init()

	// Any additional setup and cleanup can be performed here if you like.
	// This would be done using testenv.Setup() and testenv.Finish() respectively.
	//
	// These take a list of functions to register at test start and test end that can be
	// used to maniplate the test context and test environment.
	//
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

func TestSkeletonBasic(t *testing.T) {
	// Grab the minimum kernel version in all cluster nodes and define an RPC checker with it
	kversion := helpers.GetMinKernelVersion(t, runner.Environment)
	// Create an curl event checker with a limit or 10 events or 30 seconds, whichever comes first
	curlChecker := curlEventChecker(kversion).WithEventLimit(100).WithTimeLimit(30 * time.Second)

	metricsChecker := metricschecker.NewMetricsChecker("skeletonMetricsChecker")

	// Define test features here. These can be used to perform actions like:
	// - Spawning an event checker and running checks
	// - Modifying resources in the cluster
	// - etc.

	// This starts curlChecker and uses it to run event checks.
	runEventChecker := features.New("Run Event Checks").
		Assess("Run Event Checks", curlChecker.CheckInNamespace(1*time.Minute, namespace)).Feature()

	// This feature waits for curlChecker to start then runs a custom workload.
	runWorkload := features.New("Run Workload").
		/* Wait up to 30 seconds for the event checker to start before continuing */
		Assess("Wait for Checker", curlChecker.Wait(30*time.Second)).
		/* Run the workload */
		Assess("Run Workload", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString(namespace, curlPod, true)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to spawn workload")
				t.Fail()
			}
			return ctx
		}).
		Assess("Run Metrics Checks", metricsChecker.Greater("tetragon_events_total", 0)).
		Assess("Uninstall policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.UnloadCRDString(namespace, curlPod, true)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to spawn workload")
				t.Fail()
			}
			return ctx
		}).Feature()

	// We run our features using testenv.Test() or testenv.TestInParallel(). These take
	// a *testing.T as an argument as well as a list of features to execute.
	//
	// TestInParallel() works the same as Test() except it will execute features in
	// parallel. In Tetragon e2e tests, TestInParallel() is primarily used to run event
	// checkers while spawing a work load.
	//
	// This particular testenv.TestInParallel() starts our event checker, waits for it to
	// start, and then runs our workload.
	runner.TestInParallel(t, runEventChecker, runWorkload)
}

// nolint:revive // ignore unused parameter because of comments
func curlEventChecker(kernelVersion string) *checker.RPCChecker {
	curlEventChecker := ec.NewUnorderedEventChecker(
		// Checkers should be given a unique name. This shows up in the logs and can be
		// helpful when debugging failures and flakes.
		ec.NewProcessExecChecker("checkerNameHere").
			WithProcess(
				ec.NewProcessChecker().
					WithPod(ec.NewPodChecker().
						WithNamespace(sm.Full(namespace))).
					WithBinary(sm.Suffix("curl")),
			),
	)

	/* // Kernel version-specific checks can be added like so:
	 * if kernels.KernelStringToNumeric(kernelVersion) >= kernels.KernelStringToNumeric("5.10.0") {
	 *     curlEventChecker.AddChecks(
	 *         // You would put your event checks here
	 *     )
	 * }
	 */

	return checker.NewRPCChecker(curlEventChecker, "curlEventChecker")
}

const curlPod = `
apiVersion: batch/v1
kind: Job
metadata:
  name: curl
  labels:
    app: curl
spec:
  template:
    spec:
      containers:
        - name: curl
          image: docker.io/curlimages/curl:latest
          imagePullPolicy: Always
          command: ["curl"]
          args: ["http://www.google.ca"]
      restartPolicy: Never
  backoffLimit: 4
`
