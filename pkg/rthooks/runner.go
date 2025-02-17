// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"context"
	"fmt"

	v1 "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/watcher"
	"go.uber.org/multierr"
)

type Runner struct {
	callbacks []Callbacks
	watcher   watcher.PodAccessor
}

// RunHooks executes all registered callbacks
func (r *Runner) RunHooks(ctx context.Context, req *v1.RuntimeHookRequest) error {
	if createReq := req.GetCreateContainer(); createReq != nil {
		var ret error
		for _, cbs := range r.callbacks {
			if fn := cbs.CreateContainer; fn != nil {
				err := fn(ctx, &CreateContainerArg{
					Req:     createReq,
					Watcher: r.watcher,
				})
				ret = multierr.Append(ret, err)
			}
		}
		return ret
	}

	return fmt.Errorf("unknown RuntimeHookRequest type: %T", req.Event)
}

// registerCallbacks registers a set of callbacks to the runner
func (r *Runner) registerCallbacks(cbs Callbacks) {
	r.callbacks = append(r.callbacks, cbs)
}

// WithWatcher sets the watcher on a runner
func (r *Runner) WithWatcher(watcher watcher.PodAccessor) *Runner {
	r.watcher = watcher
	return r
}
