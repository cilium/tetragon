// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/option"
)

const (
	debugMsgMaxLen = 4096 // Match BPF_DEBUG_DATA_MAX_LEN
)

// Message represents a debug message from eBPF
type Message struct {
	Timestamp uint64
	PID       uint32
	CPU       uint32
	Data      [debugMsgMaxLen]byte
}

// StartDebugReader starts the debug message reader
func StartDebugReader(ctx context.Context) error {
	if !option.Config.EnablePerfDebug {
		return nil
	}

	return startPlatformDebugReader(ctx)
}

// parseDebugEvent parses a raw debug event from the buffer/ringbuf
func parseDebugEvent(data []byte) *Message {
	var event Message
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
		log.Printf("Failed to parse debug event: %v (size: %d)", err, len(data))
		return nil
	}
	return &event
}

// printDebugMessage formats and prints a debug message
func printDebugMessage(event *Message) {
	// Convert timestamp to readable format
	timestamp := time.Unix(0, int64(event.Timestamp))

	// Extract the null-terminated string from the data buffer
	msg := extractNullTerminatedString(event.Data[:])

	// Print formatted debug message
	fmt.Printf("[%s] DEBUG[cpu=%d,pid=%d]: %s\n",
		timestamp.Format("15:04:05.000000"),
		event.CPU,
		event.PID,
		msg,
	)
}

func extractNullTerminatedString(data []byte) string {
	nullIndex := bytes.IndexByte(data, 0)
	if nullIndex == -1 {
		// No null terminator found, use entire buffer (shouldn't happen with bpf_snprintf)
		return strings.TrimSpace(string(data))
	}
	return string(data[:nullIndex])
}
