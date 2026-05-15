// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package main

import (
	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/option"
)

// registerCgidmapPodHandlers wires cgidmap into the supplied pod-event source
// when the cgidmap feature is enabled. cgidmap is unavailable on Windows, so
// this function is built only for non-Windows targets.
func registerCgidmapPodHandlers(events manager.PodEventSource) {
	if !option.Config.EnableCgIDmap {
		return
	}
	if err := cgidmap.Register(events); err != nil {
		log.Warn("failed to register cgidmap pod handlers", logfields.Error, err)
	}
}
