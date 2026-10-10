// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/watcher"
)

type dummyNotifier struct {
	listeners []server.Listener
}

func (d *dummyNotifier) AddListener(listener server.Listener) {
	d.listeners = append(d.listeners, listener)
}

func (d *dummyNotifier) RemoveListener(listener server.Listener) {
	for i, l := range d.listeners {
		if l == listener {
			d.listeners = append(d.listeners[:i], d.listeners[i+1:]...)
			return
		}
	}
}

func (d *dummyNotifier) NotifyListener(_ any, _ *tetragon.GetEventsResponse) {}

type dummyMessage struct {
	retriesInternal int
	retries         int
}

func (msg *dummyMessage) Notify() bool {
	return true
}

func (msg *dummyMessage) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	tid := uint32(5)
	msg.retriesInternal++
	return HandleGenericInternal(ev, 0, &tid, timestamp)
}

func (msg *dummyMessage) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	tid := uint32(5)
	msg.retries++
	return HandleGenericEvent(internal, ev, &tid)
}

func (msg *dummyMessage) HandleMessage() *tetragon.GetEventsResponse {
	return nil
}

func (msg *dummyMessage) Cast(_ any) notify.Message {
	return nil
}

func TestEventCache(t *testing.T) {
	d := dummyNotifier{}
	tetragonEvent := &tetragon.ProcessTracepoint{
		Process:    &tetragon.Process{},
		Parent:     &tetragon.Process{},
		Subsys:     "subsys",
		Event:      "event",
		PolicyName: "policy",
	}
	msg := dummyMessage{}

	synctest.Test(t, func(t *testing.T) {
		ec := NewWithTimer(t.Context(), &d, time.Millisecond*5)
		require.NotNil(t, ec)

		err := process.InitCache(t.Context(), watcher.NewFakeK8sWatcher(nil), 10, defaults.DefaultProcessCacheGCInterval)
		require.NoError(t, err)

		// Add an event without a processInternal to let the cache trigger a retry internally after 5ms
		ec.Add(nil, tetragonEvent, uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano()-5), &msg)
		synctest.Sleep(time.Millisecond * 6)

		// not called
		require.Equal(t, 0, msg.retries)
		// called internally by the cache loop() method
		require.Equal(t, 1, msg.retriesInternal)
	})
}
