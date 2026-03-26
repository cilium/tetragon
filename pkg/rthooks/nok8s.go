// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

// dummy rthooks implementation for nok8s bulds.

package rthooks

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type Runner struct{}

var (
	globalRunner = &Runner{}
)

func (r *Runner) RunHooks(
	ctx context.Context,
	req *tetragon.RuntimeHookRequest) error {
	return nil
}

func (r *Runner) WithWatcher(podWatcher any) *Runner {
	return r
}

func GlobalRunner() *Runner {
	return globalRunner
}
