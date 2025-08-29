// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// startPlatformDebugReader starts the Linux-specific debug message reader using perf buffers
func startPlatformDebugReader(ctx context.Context) error {
	// Get the debug_events perf map using Tetragon's standard path construction
	debugMapPath := filepath.Join(bpf.MapPrefixPath(), "debug_events")
	pinOpts := ebpf.LoadPinOptions{}
	debugMap, err := ebpf.LoadPinnedMap(debugMapPath, &pinOpts)
	if err != nil {
		return fmt.Errorf("opening pinned debug_events map failed: %w", err)
	}
	defer debugMap.Close()

	// Create perf event reader
	reader, err := perf.NewReader(debugMap, 1<<16) // 4KB buffer per CPU
	if err != nil {
		return fmt.Errorf("failed to create perf reader: %w", err)
	}

	// Start reading debug events in a goroutine
	go func() {
		defer reader.Close()

		for ctx.Err() == nil {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}

				// Only log errors if context hasn't been cancelled
				if ctx.Err() == nil {
					logger.GetLogger().Error("Error reading debug event", logfields.Error, err)
				}
				continue
			}

			// Parse and print the debug message
			if msg := parseDebugEvent(record.RawSample); msg != nil {
				printDebugMessage(msg)
			}
		}
	}()

	logger.GetLogger().Info("Reading debug events from buffer")
	return nil
}
