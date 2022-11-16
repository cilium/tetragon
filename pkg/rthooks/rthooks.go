// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package rthooks contains code for managing run-time hooks
// Runtime hooks are hooks for (synchronously) notifying the agent for runtime
// events such as the creation of a container.
package rthooks

import (
	"context"

	v1 "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/watcher"
)

var (
	globalRunner = &Runner{}
)

// rthooks  provides a way for the gRPC server code to trigger sensor-specific
// code when a RuntimeHookRequest is issued.
//
// Specifically:
//  - sensors can register their callbacks at init() using RegisterCallbacksAtInit
//    which registers in these hooks in globalRunner.
//  - after init(), GlobalRunner() can be used to retrieve this runner and pass
//    it to the gRPC server code so that it can execute these callbacks when a
//    RuntimeHookRequest is issued.
//  - some of these hooks need access to pkg/watcher, so before passing the
//    runner to gRPC server, we add the watcher as well. Hooks can access the
//    watcher via the argument passed in the executed callback.

// RegisterCallbacksAtInit registers callbacks (should be called at init())
func RegisterCallbacksAtInit(cbs Callbacks) {
	if globalRunner == nil {
		panic("global runner not set: RegisiterCallbackAtInit must be called in an init()")
	}
	globalRunner.registerCallbacks(cbs)
}

// After RegisterCallbacksAtInit(), this function can be used to retrieve the Runner.
// Once this function is called, subsequent calls of RegisterCallbacksAtInit() will panic()
func GlobalRunner() *Runner {
	if globalRunner == nil {
		panic("GlobalRunner() should only be called once, after all init()s")
	}
	ret := globalRunner
	globalRunner = nil
	return ret
}

type CreateContainerArg struct {
	Req     *v1.CreateContainer
	Watcher watcher.K8sResourceWatcher
}

type Callbacks struct {
	CreateContainer func(ctx context.Context, arg *CreateContainerArg) error
}
