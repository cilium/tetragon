// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouprate

import (
	"context"
	"io"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/sirupsen/logrus"
)

var (
	handle     *CgroupRate
	handleLock sync.RWMutex
)

type Listener interface {
	Notify(msg notify.Message) error
	io.Closer
}

type CgroupRate struct {
	listeners map[Listener]struct{}
	log       logrus.FieldLogger
}

func NewCgroupRate(ctx context.Context) *CgroupRate {
	handleLock.Lock()
	defer handleLock.Unlock()

	handle = &CgroupRate{
		listeners: make(map[Listener]struct{}),
		log:       logger.GetLogger(),
	}
	go handle.process(ctx)
	return handle
}

func (r *CgroupRate) AddListener(listener Listener) {
	r.listeners[listener] = struct{}{}
}

func (r *CgroupRate) RemoveListener(listener Listener) {
	delete(r.listeners, listener)
	if err := listener.Close(); err != nil {
		r.log.WithError(err).Warn("failed to close listener")
	}
}

func (r *CgroupRate) Notify(msg notify.Message) {
	for listener := range r.listeners {
		if err := listener.Notify(msg); err != nil {
			r.log.WithError(err).Warn("failed to notify listener")
			r.RemoveListener(listener)
		}
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
