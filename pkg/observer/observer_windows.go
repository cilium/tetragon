// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

func (k *Observer) RunEvents(stopCtx context.Context, ready func()) error {
	coll, err := bpf.GetCollection("ProcessMonitor")
	if coll == nil {
		return errors.New("exec Preloaded collection is nil")
	}
	ringBufMap := coll.Maps["process_ringbuf"]
	reader := bpf.GetNewWindowsRingBufReader()
	err = reader.Init(ringBufMap.FD(), int(ringBufMap.MaxEntries()))
	if err != nil {
		return fmt.Errorf("failed initializing ringbuf reader: %w", err)
	}
	// Inform caller that we're about to start processing events.
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through winEventsQueue channel.
	winEventsQueue := make(chan *bpf.Record, k.getRBQueueSize())

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	k.log.Info("Listening for events...")

	// Start reading records from the perf array. Reads until the reader is closed.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	go func() {
		defer wg.Done()
	}()

	go func() {
		defer wg.Done()

		for stopCtx.Err() == nil {
			var record bpf.Record
			record, errCode := reader.GetNextRecord()
			if (errCode == bpf.ERR_RINGBUF_OFFSET_MISMATCH) || (errCode == bpf.ERR_RINGBUF_UNKNOWN_ERROR) {
				k.log.Warn("Reading bpf events failed", "NewError", 0, logfields.Error, err)
				break
			}
			if (errCode == bpf.ERR_RINGBUF_RECORD_DISCARDED) || (errCode == bpf.ERR_RINGBUF_TRY_AGAIN) {
				continue
			}
			if len(record.RawSample) > 0 {
				select {
				case winEventsQueue <- &record:
				default:
					// drop the event, since channel is full
					queueLost.Inc()
				}
				RingbufReceived.Inc()
			}
			if record.LostSamples > 0 {
				RingbufLost.Add(float64(record.LostSamples))
			}
		}
	}()

	// Start processing records from ringbuffer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case winEvent := <-winEventsQueue:
				k.receiveEvent(winEvent.RawSample)
				queueReceived.Inc()
			case <-stopCtx.Done():
				k.log.Info("Listening for events completed.", logfields.Error, stopCtx.Err())
				k.log.Debug(fmt.Sprintf("Unprocessed events in RB queue: %d", len(winEventsQueue)))
				return
			}
		}
	}()

	// Loading default program consumes some memory lets kick GC to give
	// this back to the OS (K8s).
	go func() {
		runtime.GC()
	}()

	// Wait for context to be cancelled and then stop.
	<-stopCtx.Done()
	return nil
}
