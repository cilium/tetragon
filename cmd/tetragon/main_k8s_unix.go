// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package main

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/tracing"
)

// EnableCgIDmap wires cgidmap into the supplied pod-event source
// when the cgidmap feature is enabled. cgidmap is unavailable on Windows, so
// this function is built only for non-Windows targets.
func EnableCgIDmap(src events.PodEventSource) error {
	if !option.Config.EnableCgIDmap {
		return nil
	}
	if err := cgidmap.Register(src); err != nil {
		return fmt.Errorf("failed to register cgidmap pod handlers: %w", err)
	}
	return nil
}

// EnableUprobeResolvePathInContainer wires the resolvePathInContainer uprobe pod-event
// handlers into the supplied pod-event source. The handlers live in the tracing
// package, which is excluded from Windows builds, so this wiring is non-Windows
// only.
func EnableUprobeResolvePathInContainer(src events.PodEventSource) error {
	if err := tracing.RegisterResolvePathInContainerPodHandlers(src); err != nil {
		return fmt.Errorf("failed to register resolvePathInContainer uprobe pod handlers: %w", err)
	}
	return nil
}
