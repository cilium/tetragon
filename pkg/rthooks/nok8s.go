// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package rthooks

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type Runner struct{}

func (r *Runner) RunHooks(
	ctx context.Context,
	req *tetragon.RuntimeHookRequest) error {
	return nil
}
