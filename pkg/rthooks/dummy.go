// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type DummyHookRunner struct{}

func (o DummyHookRunner) RunHooks(ctx context.Context, req *tetragon.RuntimeHookRequest) error {
	return nil
}
