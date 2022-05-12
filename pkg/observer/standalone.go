// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"fmt"

	"github.com/isovalent/tetragon-oss/pkg/logger"
)

type standaloneListener struct {
}

func (sl *standaloneListener) Notify(msg interface{}) error {
	_, err := fmt.Printf("=> %v\n", msg)
	return err
}

func (sl *standaloneListener) Close() error {
	return nil
}

func (k *Observer) StartStandalone(ctx context.Context) error {
	if len(k.listeners) > 0 {
		return fmt.Errorf("hubble-fgs, Cowardly refusing to start in standalone mode with other listeners registered")
	}
	logger.GetLogger().Info("starting observer in standalone mode")
	k.AddListener(&standaloneListener{})
	return k.Start(ctx)
}
