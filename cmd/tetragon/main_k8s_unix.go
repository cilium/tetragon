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

// EnableCgIDmap wires cgidmap into the pod-event source when the feature is
// enabled. cgidmap is unavailable on Windows.
func EnableCgIDmap(src events.PodEventSource) error {
	if !option.Config.EnableCgIDmap {
		return nil
	}
	if err := cgidmap.Register(src); err != nil {
		return fmt.Errorf("failed to register cgidmap pod handlers: %w", err)
	}
	return nil
}

// EnableUprobeResolvePathInContainer wires the resolvePathInContainer uprobe
// pod-event handlers into the pod-event source.
func EnableUprobeResolvePathInContainer(src events.PodEventSource) error {
	if err := tracing.RegisterResolvePathInContainerPodHandlers(src); err != nil {
		return fmt.Errorf("failed to register resolvePathInContainer uprobe pod handlers: %w", err)
	}
	return nil
}
