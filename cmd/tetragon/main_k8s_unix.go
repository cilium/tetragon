// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package main

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/option"
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
