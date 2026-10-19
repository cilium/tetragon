// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && nok8s

package policytest

import (
	"errors"
	"io"
	"time"

	"github.com/spf13/pflag"
)

var errNoK8s = errors.New("tetra was built without Kubernetes support")

// k8sFlags registers no flags, so enabled stays false.
type k8sFlags struct {
	enabled bool
}

func (*k8sFlags) register(*pflag.FlagSet) {}

func (*k8sFlags) run(io.Writer, time.Duration, []string) error {
	return errNoK8s
}
