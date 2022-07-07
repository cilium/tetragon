// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium-e2e/pkg/e2ecluster/e2ehelpers"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/state"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

func PortForwardTetragonPods(testenv env.Environment) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
		if !ok {
			return ctx, fmt.Errorf("failed to find Tetragon install options. Did the test setup install Tetragon?")
		}

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(opts.Namespace)

		podList := &corev1.PodList{}
		if err = r.List(
			ctx,
			podList,
			resources.WithLabelSelector(fmt.Sprintf("app.kubernetes.io/name=%s", opts.DaemonSetName)),
		); err != nil {
			return ctx, err
		}

		// TODO: do we need to make this configurable at some point?
		const (
			grpcPort = 54321
			promPort = 2112
		)

		grpcPorts := make(map[string]int)
		promPorts := make(map[string]int)
		for i, pod := range podList.Items {
			if ctx, err = e2ehelpers.PortForwardPod(
				testenv,
				&pod,
				nil,
				os.Stderr,
				30,
				time.Second,
				fmt.Sprintf("%d:%d", grpcPort+i, grpcPort),
				fmt.Sprintf("%d:%d", promPort+i, promPort),
			)(ctx, cfg); err != nil {
				return ctx, err
			}
			grpcPorts[pod.Name] = grpcPort + i
			promPorts[pod.Name] = promPort + i
		}

		ctx = context.WithValue(ctx, state.GrpcForwardedPorts, grpcPorts)
		ctx = context.WithValue(ctx, state.PromForwardedPorts, promPorts)

		klog.InfoS("Successfully forwarded ports for Tetragon pods", "grpcPorts", grpcPorts, "promPorts", promPorts)

		return ctx, nil
	}
}
