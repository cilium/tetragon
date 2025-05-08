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
)

func (observer *Observer) RunEvents(stopCtx context.Context, ready func()) error {
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
	observer.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through winEventsQueue channel.
	winEventsQueue := make(chan *bpf.Record, observer.getRBQueueSize())

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	observer.log.Info("Listening for events...")

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
				observer.log.WithField("NewError ", 0).WithError(err).Warn("Reading bpf events failed")
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
				observer.receiveEvent(winEvent.RawSample)
				queueReceived.Inc()
			case <-stopCtx.Done():
				observer.log.WithError(stopCtx.Err()).Infof("Listening for events completed.")
				observer.log.Debugf("Unprocessed events in RB queue: %d", len(winEventsQueue))
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
