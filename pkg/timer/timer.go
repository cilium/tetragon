// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package timer

import (
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
)

type PeriodicTimer struct {
	mu       sync.Mutex
	running  bool
	stop     chan bool
	wg       sync.WaitGroup
	unit     string
	dowork   func()
	verbose  bool
	interval time.Duration
}

func NewPeriodicTimer(name string, timerWorker func(), verbose bool) *PeriodicTimer {
	return &PeriodicTimer{
		running: false,
		unit:    name,
		dowork:  timerWorker,
		verbose: verbose,
	}
}

func (t *PeriodicTimer) Start(newInterval time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if newInterval <= 0 {
		logger.GetLogger().Warn(t.unit + ": invalid interval specified (<= 0)")
		return
	}

	if t.running {
		if newInterval == t.interval {
			if t.verbose {
				logger.GetLogger().Warn(t.unit + " start: already running")
			}
			return
		}
		t.stop <- true
		t.wg.Wait()
	}

	t.interval = newInterval
	t.running = true
	t.wg.Add(1)
	t.stop = make(chan bool)
	go t.worker(t.interval)
}

func (t *PeriodicTimer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		if t.verbose {
			logger.GetLogger().Warn(t.unit + " stop: not started")
		}
		return
	}

	t.stop <- true
	t.wg.Wait()
	t.running = false

	if t.verbose {
		logger.GetLogger().Info(t.unit + " stopped")
	}
}

func (t *PeriodicTimer) worker(interval time.Duration) {
	defer t.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if t.verbose {
		logger.GetLogger().Info(t.unit + " started")
	}

	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			t.dowork()
		}
	}
}
