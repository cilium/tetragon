// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package main

import (
	"context"

	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/watcher"
)

func initK8s(ctx context.Context) (watcher.PodAccessor, error) {
	return nil, nil
}

func getHooksRunner(_ watcher.PodAccessor) *rthooks.Runner {
	return nil
}

func initK8sPolicyWatcher(ctx context.Context) error {
	return nil
}

func initK8sMetrics() {}
