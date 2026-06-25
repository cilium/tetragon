// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build windows && !nok8s

package main

import "github.com/cilium/tetragon/pkg/manager/events"

// EnableCgIDmap is a no-op on Windows, where cgidmap is unavailable.
func EnableCgIDmap(_ events.PodEventSource) error { return nil }

// EnableUprobeResolvePathInContainer is a no-op on Windows.
func EnableUprobeResolvePathInContainer(_ events.PodEventSource) error { return nil }
