// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build windows && !nok8s

package main

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/manager/events"
)

// EnableCgIDmap is a no-op on Windows, where cgidmap is unavailable.
func EnableCgIDmap(_ events.PodEventSource) error { return nil }

// EnableUprobeResolvePathInContainer is a no-op on Windows.
func EnableUprobeResolvePathInContainer(_ events.PodEventSource, _ func() ([]*corev1.Pod, error)) error {
	return nil
}
