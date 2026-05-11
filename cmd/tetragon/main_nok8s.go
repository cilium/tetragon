// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package main

import (
	"context"

	"github.com/cilium/tetragon/pkg/watcher"
)

func initK8s(_ context.Context) (watcher.PodAccessor, error) {
	return nil, nil
}

func initK8sPolicyWatcher() error {
	return nil
}

func initK8sMetrics() {}
