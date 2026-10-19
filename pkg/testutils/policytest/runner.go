// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"iter"
	"log/slog"
)

// Runner runs a selection of policy tests.
type Runner interface {
	// Run yields one result per test and parameter set. An error ends the
	// sequence and comes with a nil result. A Runner can run again after Run
	// returns.
	Run(ctx context.Context, log *slog.Logger, sel *Selection) iter.Seq2[*NamedResult, error]
	// Close releases what the Runner holds on to.
	Close() error
}
