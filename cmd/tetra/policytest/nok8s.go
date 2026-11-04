// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && nok8s

package policytest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

var errNoK8s = errors.New("tetra was built without Kubernetes support")

// k8sFlags registers no flags, so enabled stays false.
type k8sFlags struct {
	enabled bool
}

func (*k8sFlags) register(*pflag.FlagSet) {}

func (*k8sFlags) check(*pflag.FlagSet) error { return nil }

func (*k8sFlags) runner(context.Context, *slog.Logger, time.Duration, io.Writer) (policytest.Runner, error) {
	return nil, errNoK8s
}
