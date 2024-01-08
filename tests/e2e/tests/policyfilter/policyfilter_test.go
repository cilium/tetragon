// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/helpers/grpc"
	"github.com/cilium/tetragon/tests/e2e/runners"
	"github.com/sirupsen/logrus"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// This holds our test environment which we get from calling runners.NewRunner().Setup()
var runner *runners.Runner

var (
	// Basic Tetragon parameters
	TetragonNamespace  = "kube-system"
	TetragonAppNameKey = "app.kubernetes.io/name"
	TetragonAppNameVal = "tetragon"
	TetragonContainer  = "tetragon"
	TetragonCLI        = "tetra"
)

var (
	// for the namespace test, we:
	//  - create two namespaces and start a pod in each of them
	//  - install a policy for monitoring syscalls in one of them (on sys_enter)
	//  - check that we get events only from that namespace, and not the other.
	otherNamespace  = "ns1"
	policyNamespace = "ns2"

	// for the pod label filter test, we:
	//  - create a namespace
	//  - install a namespaced policy with pod label filter in that namespace (on sys_exit)
	//  - create two pods, one that matches the policy and one that does not
	//  - check that we only receive events from the first
	podlblNamespace = "nslabel"

	testNamespaces = []string{otherNamespace, policyNamespace, podlblNamespace}
)

func TestMain(m *testing.M) {
	runner = runners.NewRunner().Init()

	// Here we ensure our test namespace doesn't already exist then create it.
	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		for _, ns := range testNamespaces {
			klog.Infof("Deleting and recreating namespace %s", ns)
			ctx, _ = helpers.DeleteNamespace(ns, true)(ctx, c)
			ctx, err := helpers.CreateNamespace(ns, true)(ctx, c)
			if err != nil {
				return ctx, fmt.Errorf("failed to create namespace: %w", err)
			}
		}
		return ctx, nil
	})

	// Run the tests using the test runner.
	runner.Run(m)
}

func TestNamespacedPolicy(t *testing.T) {
	runner.SetupExport(t)

	checker := nsChecker().WithTimeLimit(30 * time.Second).WithEventLimit(20)

	runEventChecker := features.New("Run Event Checks").
		Assess("Run Event Checks", checker.CheckWithFilters(
			30*time.Second,
			// allow list
			[]*tetragon.Filter{{
				EventSet:  []tetragon.EventType{tetragon.EventType_PROCESS_TRACEPOINT},
				Namespace: []string{otherNamespace, policyNamespace},
			}},
			// deny list
			[]*tetragon.Filter{},
		)).Feature()

	runWorkload := features.New("Namespaced policy test").
		Assess("Install policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString(policyNamespace, namespacedPolicy, false)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to install policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for policy", func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			if err := grpc.WaitForTracingPolicy(ctx, "syscalls"); err != nil {
				klog.ErrorS(err, "failed to wait for policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for Checker", checker.Wait(30*time.Second)).
		Assess("Start pods", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			var err error
			for _, ns := range []string{policyNamespace, otherNamespace} {
				ctx, err = helpers.LoadCRDString(ns, ubuntuPod, true)(ctx, c)
				if err != nil {
					klog.ErrorS(err, "failed to load pod")
					t.Fail()
				}

			}
			return ctx
		}).
		Assess("Uninstall policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.UnloadCRDString(policyNamespace, namespacedPolicy, false)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to uninstall policy")
				t.Fail()
			}
			return ctx
		}).
		Feature()

	runner.TestInParallel(t, runWorkload, runEventChecker)
}

const namespacedPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "syscalls"
spec:
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "int64"
`

const ubuntuPod = `
kind: Deployment
apiVersion: apps/v1
metadata:
  name: ubuntu
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ubuntu
  template:
    metadata:
      labels:
        app: ubuntu
    spec:
      containers:
      - name: ubuntu
        image: ubuntu:20.04
        imagePullPolicy: Always
        command: ["bash"]
        args: ["-c", "while sleep 1; do cat /etc/hostname; done"]
`

func nsChecker() *checker.RPCChecker {
	return checker.NewRPCChecker(&namespaceChecker{}, "policyfilter-namespace-checker")
}

type namespaceChecker struct {
	matches int
}

func (nsc *namespaceChecker) NextEventCheck(event ec.Event, _ *logrus.Logger) (bool, error) {
	// ignore non-trace point events
	ev, ok := event.(*tetragon.ProcessTracepoint)
	if !ok {
		return false, errors.New("not a tracepoint")
	}

	// ignore other tracepoints
	if ev.GetSubsys() != "raw_syscalls" || ev.GetEvent() != "sys_enter" {
		return false, fmt.Errorf("not raw_syscalls:sys_enter (%s:%s instead)", ev.GetSubsys(), ev.GetEvent())
	}

	if ev.GetProcess().GetPod().GetNamespace() != policyNamespace {
		return true, fmt.Errorf("event %+v has wrong policy namespace", ev)
	}

	nsc.matches++
	return false, nil
}

func (nsc *namespaceChecker) FinalCheck(_ *logrus.Logger) error {
	if nsc.matches > 0 {
		return nil
	}
	return fmt.Errorf("namespace checker failed, had %d matches", nsc.matches)
}

func TestPodLabelFilters(t *testing.T) {
	runner.SetupExport(t)

	checker := podlblChecker().WithTimeLimit(30 * time.Second).WithEventLimit(20)

	runEventChecker := features.New("Run Event Checks").
		Assess("Run Event Checks", checker.CheckWithFilters(
			30*time.Second,
			// allow list
			[]*tetragon.Filter{{
				EventSet:  []tetragon.EventType{tetragon.EventType_PROCESS_TRACEPOINT},
				Namespace: []string{podlblNamespace},
			}},
			// deny list
			[]*tetragon.Filter{},
		)).Feature()

	runWorkload := features.New("Pod label filter test").
		Assess("Install policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString(podlblNamespace, podlblPolicy, false)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to install policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for policy", func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			if err := grpc.WaitForTracingPolicy(ctx, "l1-syscalls"); err != nil {
				klog.ErrorS(err, "failed to wait for policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for Checker", checker.Wait(30*time.Second)).
		Assess("Start pods", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			var err error
			for _, pod := range []string{ubuntuPod_l1, ubuntuPod_l2} {
				ctx, err = helpers.LoadCRDString(podlblNamespace, pod, true)(ctx, c)
				if err != nil {
					klog.ErrorS(err, "failed to load pod")
					t.Fail()
				}

			}
			return ctx
		}).
		Assess("Uninstall policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.UnloadCRDString(podlblNamespace, podlblPolicy, false)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to uninstall policy")
				t.Fail()
			}
			return ctx
		}).
		Feature()

	runner.TestInParallel(t, runWorkload, runEventChecker)
}

const podlblPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "l1-syscalls"
spec:
  podSelector:
     matchLabels:
        app: "ubuntu-l1"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_exit"
    args:
    - index: 4
      type: "int64"
`

const ubuntuPod_l1 = `
kind: Deployment
apiVersion: apps/v1
metadata:
  name: ubuntu-l2
spec:
  replicas: 1
  selector:
    matchLabels:
      app: "ubuntu-l1"
  template:
    metadata:
      labels:
        app: "ubuntu-l1"
    spec:
      containers:
      - name: ubuntu
        image: ubuntu:20.04
        imagePullPolicy: Always
        command: ["bash"]
        args: ["-c", "while sleep 1; do cat /etc/hostname; done"]
`

const ubuntuPod_l2 = `
kind: Deployment
apiVersion: apps/v1
metadata:
  name: ubuntu-l1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: "ubuntu-l2"
  template:
    metadata:
      labels:
        app: "ubuntu-l2"
    spec:
      containers:
      - name: ubuntu
        image: ubuntu:20.04
        imagePullPolicy: Always
        command: ["bash"]
        args: ["-c", "while sleep 1; do cat /etc/hostname; done"]
`

func podlblChecker() *checker.RPCChecker {
	return checker.NewRPCChecker(&podLabelChecker{}, "policyfilter-pod-label-checker")
}

type podLabelChecker struct {
	matches int
}

func (plc *podLabelChecker) NextEventCheck(event ec.Event, _ *logrus.Logger) (bool, error) {
	// ignore non-trace point events
	ev, ok := event.(*tetragon.ProcessTracepoint)
	if !ok {
		return false, errors.New("not a tracepoint")
	}

	// ignore other tracepoints
	if ev.GetSubsys() != "raw_syscalls" || ev.GetEvent() != "sys_exit" {
		return false, fmt.Errorf("not raw_syscalls:sys_exit (%s:%s instead)", ev.GetSubsys(), ev.GetEvent())
	}

	labels := ev.GetProcess().GetPod().GetPodLabels()
	if labels == nil {
		return true, fmt.Errorf("event %+v has no labels", ev)
	}

	if val, ok := labels["app"]; !ok || val != "ubuntu-l1" {
		return true, fmt.Errorf("event %+v has wrong label labels", ev)
	}

	plc.matches++
	return false, nil
}

func (plc *podLabelChecker) FinalCheck(_ *logrus.Logger) error {
	if plc.matches > 0 {
		return nil
	}
	return fmt.Errorf("pod-label checker failed, had %d matches", plc.matches)
}
