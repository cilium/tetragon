// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package rthooks contains code for managing run-time hooks
//
// Runtime hooks are hooks for (synchronously) notifying the agent for runtime
// events such as the creation of a container.
//
// Different parts of the agent can register callbacks that will run sequentially when a
// RuntimeHookRequest is issued.
//
// Specifically:
//   - sensors can register their callbacks at init() using RegisterCallbacksAtInit
//     which registers in these hooks in globalRunner.
//   - after init(), GlobalRunner() can be used to retrieve this runner and pass
//     it to the gRPC server code so that it can execute these callbacks when a
//     RuntimeHookRequest is issued.
//   - some of these hooks need access to pkg/watcher, so before passing the
//     runner to gRPC server, we add the watcher as well. Hooks can access the
//     watcher via the argument passed in the executed callback.
//   - all callbacks are executed, i.e., if a callback returns an error execution of callbacks does
//     not stop
//   - if any callback fails with an error, the gRPC server will return an error to the client (see
//     pkg/server/server.go)

//go:build k8s

package rthooks

import (
	"context"
)

var (
	globalRunner = &Runner{}
)

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

type Callbacks struct {
	CreateContainer func(ctx context.Context, arg *CreateContainerArg) error
}
