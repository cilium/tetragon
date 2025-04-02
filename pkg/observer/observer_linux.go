// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/api/readyapi"
)

func (k *Observer) RunEvents(stopCtx context.Context, ready func()) error {
	pinOpts := ebpf.LoadPinOptions{}
	perfMap, err := ebpf.LoadPinnedMap(k.PerfConfig.MapName, &pinOpts)
	if err != nil {
		return fmt.Errorf("opening pinned map '%s' failed: %w", k.PerfConfig.MapName, err)
	}
	defer perfMap.Close()

	rbSize := k.getRBSize(int(perfMap.MaxEntries()))
	perfReader, err := perf.NewReader(perfMap, rbSize)

	if err != nil {
		return fmt.Errorf("creating perf array reader failed: %w", err)
	}

	// Inform caller that we're about to start processing events.
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through eventsQueue channel.
	eventsQueue := make(chan *perf.Record, k.getRBQueueSize())

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	k.log.Info("Listening for events...")

	// Start reading records from the perf array. Reads until the reader is closed.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		for stopCtx.Err() == nil {
			record, err := perfReader.Read()
			if err != nil {
				// NOTE(JM and Djalal): count and log errors while excluding the stopping context
				if stopCtx.Err() == nil {
					RingbufErrors.Inc()
					errorCnt := getCounterValue(RingbufErrors)
					k.log.WithField("errors", errorCnt).WithError(err).Warn("Reading bpf events failed")
				}
			} else {
				if len(record.RawSample) > 0 {
					select {
					case eventsQueue <- &record:
					default:
						// eventsQueue channel is full, drop the event
						queueLost.Inc()
					}
					RingbufReceived.Inc()
				}

				if record.LostSamples > 0 {
					RingbufLost.Add(float64(record.LostSamples))
				}
			}
		}
	}()

	// Start processing records from perf.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case event := <-eventsQueue:
				k.receiveEvent(event.RawSample)
				queueReceived.Inc()
			case <-stopCtx.Done():
				k.log.WithError(stopCtx.Err()).Infof("Listening for events completed.")
				k.log.Debugf("Unprocessed events in RB queue: %d", len(eventsQueue))
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
	return perfReader.Close()
}
