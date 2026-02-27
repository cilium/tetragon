// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build synthetic

package main

import (
	"context"

	"github.com/spf13/pflag"

	"github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/synthetic"
)

func binaryName() string {
	return "tetragon-synthetic"
}

func addExtraFlags(flags *pflag.FlagSet) {
	option.AddSyntheticFlags(flags)
}

func readExtraFlags() error {
	return option.ReadAndSetSyntheticFlags()
}

func setupObserver(ctx context.Context, obs observer.EventObserver, log logger.FieldLogger) (observer.EventObserver, error) {
	if option.Config.SyntheticEventsSource != "" {
		readingObs, err := synthetic.NewReadingObserverFromFile(ctx, option.Config.SyntheticEventsSource, log)
		if err != nil {
			return nil, err
		}
		readingObs.Observer = obs.(*observer.Observer)
		return readingObs, nil
	}
	return obs, nil
}

func setupListener(ctx context.Context, obs observer.EventObserver, pm *grpc.ProcessManager, log logger.FieldLogger) error {
	if option.Config.SyntheticEventsLog != "" {
		// Create synthetic listener with ProcessManager as delegate.
		// Events are recorded before ProcessManager modifies them.
		syntheticListener, err := synthetic.NewWritingListenerToFile(
			ctx,
			option.Config.SyntheticEventsLog,
			log,
			synthetic.WithVerifyRoundtrip(option.Config.SyntheticEventsVerifyRoundtrip),
			synthetic.WithDelegate(pm),
		)
		if err != nil {
			return err
		}
		obs.AddListener(syntheticListener)
	} else {
		obs.AddListener(pm)
	}
	return nil
}
