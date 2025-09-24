// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
)

// startPlatformDebugReader starts the Windows-specific debug message reader using ringbuf
func startPlatformDebugReader(ctx context.Context) error {
	// Get the debug_events map from the Windows collection
	coll, err := bpf.GetCollection("ProcessMonitor")
	if err != nil || coll == nil {
		// If no collection exists or debug not available, silently return
		return errors.New("exec Preloaded collection is nil")
	}

	debugEventsMap := coll.Maps["debug_events"]
	if debugEventsMap == nil {
		// Debug events map not found, might not be enabled
		logger.GetLogger().Info("Debug events map not found, skipping debug reader")
		return nil
	}

	// Create a Windows ring buffer reader
	reader := bpf.GetNewWindowsRingBufReader()
	err = reader.Init(debugEventsMap.FD(), int(debugEventsMap.MaxEntries()))
	if err != nil {
		return fmt.Errorf("failed to initialize debug ringbuf reader: %w", err)
	}

	// Start reading debug events in a goroutine
	go func() {
		var wg sync.WaitGroup
		debugQueue := make(chan *bpf.Record, 1000) // Buffer for debug events
		defer wg.Done()

		// Start reader goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(debugQueue)

			for ctx.Err() == nil {
				record, errCode := reader.GetNextRecord()
				if errCode == bpf.ERR_RINGBUF_OFFSET_MISMATCH || errCode == bpf.ERR_RINGBUF_UNKNOWN_ERROR {
					logger.GetLogger().Warn("Error reading debug events from ringbuf", "errorCode", errCode)
					break
				}
				if errCode == bpf.ERR_RINGBUF_RECORD_DISCARDED || errCode == bpf.ERR_RINGBUF_TRY_AGAIN {
					continue
				}
				if len(record.RawSample) > 0 {
					select {
					case debugQueue <- &record:
					case <-ctx.Done():
						return
					default:
						// Drop event if queue is full
						logger.GetLogger().Debug("Debug event queue full, dropping event")
					}
				}
			}
		}()

		// Start event processing goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case debugEvent := <-debugQueue:
					if debugEvent == nil {
						return // Channel closed
					}
					// Parse and print the debug message
					if msg := parseDebugEvent(debugEvent.RawSample); msg != nil {
						printDebugMessage(msg)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}()

	logger.GetLogger().Info("Reading debug events from buffer")
	return nil
}
