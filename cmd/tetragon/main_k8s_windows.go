// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build windows && !nok8s

package main

import "github.com/cilium/tetragon/pkg/manager"

// registerCgidmapPodHandlers is a no-op on Windows because the cgidmap
// package is unavailable there. The shape matches the unix variant so the
// caller in main_k8s.go can call it unconditionally.
func registerCgidmapPodHandlers(_ manager.PodEventSource) {}
