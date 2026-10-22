// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"log/slog"
)

// Runner runs a selection of policy tests.
type Runner interface {
	// Run returns one result per test and parameter set that completed, and
	// an error when the run did not complete. A Runner can run again after
	// Run returns.
	Run(ctx context.Context, log *slog.Logger, sel *Selection) ([]*NamedResult, error)
	// Close releases what the Runner holds on to.
	Close() error
}
