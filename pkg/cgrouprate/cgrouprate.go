// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouprate

import (
	"context"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/sirupsen/logrus"
)

var (
	handle     *CgroupRate
	handleLock sync.RWMutex
)

type CgroupRate struct {
	listener observer.Listener
	log      logrus.FieldLogger
}

func newCgroupRate(listener observer.Listener) *CgroupRate {
	return &CgroupRate{
		listener: listener,
		log:      logger.GetLogger(),
	}
}

func NewCgroupRate(ctx context.Context,
	listener observer.Listener) {

	handleLock.Lock()
	defer handleLock.Unlock()

	handle = newCgroupRate(listener)
	go handle.process(ctx)
}

func (r *CgroupRate) notify(msg notify.Message) {
	if err := r.listener.Notify(msg); err != nil {
		r.log.WithError(err).Warn("failed to notify listener")
	}
}

func (r *CgroupRate) process(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		}
	}
}
