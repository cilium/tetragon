// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"testing"
	"time"
)

// A sensor to test the intermediate policy states (loading / unloading)

func makeTestDelayedSensor(t *testing.T) *TestDelayedSensor {
	s := &TestDelayedSensor{
		name:   "test-delayed-sensor",
		loaded: false,
		ch:     make(chan struct{}),
	}
	RegisterPolicyHandlerAtInit("dummy-policyhandler", &dummyHandler{s: s})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy-policyhandler")
	})

	return s
}

type TestDelayedSensor struct {
	name   string
	loaded bool
	ch     chan struct{}
}

func (tds TestDelayedSensor) Overhead() ([]ProgOverhead, bool) {
	return []ProgOverhead{}, false
}

func (tds TestDelayedSensor) TotalMemlock() int {
	return 0
}

func (tds *TestDelayedSensor) GetName() string {
	return tds.name
}

func (tds *TestDelayedSensor) IsLoaded() bool {
	return tds.loaded
}

func (tds *TestDelayedSensor) Load(_ string) error {
	select {
	case <-tds.ch:
	case <-time.After(10 * time.Second):
		return errors.New("TestDelayedSensor/Load timeout when waiting for unblocking")
	}
	tds.loaded = true
	return nil
}

func (tds *TestDelayedSensor) Unload(_ bool) error {
	select {
	case <-tds.ch:
	case <-time.After(10 * time.Second):
		return errors.New("TestDelayedSensor/Unload timeout when waiting for unblocking")
	}
	tds.loaded = false
	return nil
}

func (tds *TestDelayedSensor) Destroy(_ bool) {
	tds.loaded = false
}

func (tds *TestDelayedSensor) unblock(t *testing.T) {
	select {
	case tds.ch <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatalf("unblocked failed: channel does not seem to be empty")
	}

}
