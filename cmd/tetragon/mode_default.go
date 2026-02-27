// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !synthetic

package main

import (
	"context"

	"github.com/spf13/pflag"

	"github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
)

func binaryName() string {
	return "tetragon"
}

func addExtraFlags(_ *pflag.FlagSet) {}

func readExtraFlags() error {
	return nil
}

func setupObserver(_ context.Context, obs observer.EventObserver, _ logger.FieldLogger) (observer.EventObserver, error) {
	return obs, nil
}

func setupListener(_ context.Context, obs observer.EventObserver, pm *grpc.ProcessManager, _ logger.FieldLogger) error {
	obs.AddListener(pm)
	return nil
}
