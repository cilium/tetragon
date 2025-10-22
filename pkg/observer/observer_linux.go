// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/strutils"
)

const (
	perCPUBufferBytes = 65535
)

func (k *Observer) getRBSize(cpus int) int {
	var size int

	if option.Config.RBSize == 0 && option.Config.RBSizeTotal == 0 {
		size = perCPUBufferBytes
	} else if option.Config.RBSize != 0 {
		size = option.Config.RBSize
	} else {
		size = option.Config.RBSizeTotal / int(cpus)
	}

	cpuSize := perfBufferSize(size)
	totalSize := cpuSize * cpus

	k.log.Info("Perf ring buffer size (bytes)", "percpu", strutils.SizeWithSuffix(cpuSize), "total", strutils.SizeWithSuffix(totalSize))
	return size
}

// Gets final size for single perf ring buffer rounded from
// passed size argument (kindly borrowed from ebpf/cilium)
func perfBufferSize(perCPUBuffer int) int {
	pageSize := os.Getpagesize()

	// Smallest whole number of pages
	nPages := (perCPUBuffer + pageSize - 1) / pageSize

	// Round up to nearest power of two number of pages
	nPages = int(math.Pow(2, math.Ceil(math.Log2(float64(nPages)))))

	// Add one for metadata
	nPages++

	return nPages * pageSize
}

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

	var ringBufReader *ringbuf.Reader
	var ringBufMap *ebpf.Map
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		ringBufMap, err = ebpf.LoadPinnedMap(k.RingBufMapPath, &pinOpts)
		if err != nil {
			return fmt.Errorf("opening pinned map '%s' failed: %w", k.RingBufMapPath, err)
		}
		defer ringBufMap.Close()

		ringBufReader, err = ringbuf.NewReader(ringBufMap)

		if err != nil {
			return fmt.Errorf("creating ring buffer reader failed: %w", err)
		}
	}

	// Inform caller that we're about to start processing events.
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through eventsQueue channel.
	eventsQueue := make(chan []byte, k.getRBQueueSize())

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
					k.log.Warn("Reading bpf events failed", "errors", errorCnt, logfields.Error, err)
				}
			} else {
				if len(record.RawSample) > 0 {
					select {
					case eventsQueue <- record.RawSample:
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

	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		// Service the BPF ring buffer as well.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for stopCtx.Err() == nil {
				record, err := ringBufReader.Read()
				if err != nil {
					// NOTE(JM and Djalal): count and log errors while excluding the stopping context
					if stopCtx.Err() == nil {
						RingbufErrors.Inc()
						errorCnt := getCounterValue(RingbufErrors)
						k.log.Warn("Reading bpf events from BPF ring buffer failed", "errors", errorCnt, logfields.Error, err)
					}
				} else {
					if len(record.RawSample) > 0 {
						select {
						case eventsQueue <- record.RawSample:
						default:
							// eventsQueue channel is full, drop the event
							queueLost.Inc()
						}
						RingbufReceived.Inc()
					}
				}
			}
		}()
	}

	// Start processing records from perf.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case eventRawSample := <-eventsQueue:
				k.receiveEvent(eventRawSample)
				queueReceived.Inc()
			case <-stopCtx.Done():
				k.log.Info("Listening for events completed.", logfields.Error, stopCtx.Err())
				k.log.Debug(fmt.Sprintf("Unprocessed events in RB queue: %d", len(eventsQueue)))
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
	err = perfReader.Close()
	var errRingBufRdr error
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		errRingBufRdr = ringBufReader.Close()
	}
	if err != nil {
		return err
	}
	return errRingBufRdr
}
