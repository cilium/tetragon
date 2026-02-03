// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/synthetic"
)

func TestStartReady_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel when we see log message "Finished synthetic event replay"
	log := slog.New(&triggerHandler{
		Handler:   logger.SlogNopHandler,
		trigger:   "Finished synthetic event replay",
		onTrigger: cancel,
	})

	reader := strings.NewReader("{}\n{}\n{}\n")
	obs := synthetic.NewReadingObserver(reader, &testCodec{}, log)

	listener := &testListener{}
	obs.AddListener(listener)

	if err := obs.StartReady(ctx, func() {}); err != nil {
		t.Fatal(err)
	}

	if listener.received != 3 {
		t.Fatalf("expected 3 events, got %d", listener.received)
	}
}

func TestStartReady_EmptyLines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	log := slog.New(&triggerHandler{
		Handler:   logger.SlogNopHandler,
		trigger:   "Finished synthetic event replay",
		onTrigger: cancel,
	})

	reader := strings.NewReader("\n\n{}\n\n")
	obs := synthetic.NewReadingObserver(reader, &testCodec{}, log)

	listener := &testListener{}
	obs.AddListener(listener)

	if err := obs.StartReady(ctx, func() {}); err != nil {
		t.Fatal(err)
	}

	if listener.received != 1 {
		t.Fatalf("expected 1 event (empty lines skipped), got %d", listener.received)
	}
}

func TestStartReady_ContextCancel(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		pr.Close()
		pw.Close()
	})

	obs := synthetic.NewReadingObserver(pr, &testCodec{}, nopLog)

	listener := &testListener{}
	obs.AddListener(listener)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		// Write first line
		pw.Write([]byte("{}\n"))

		// Wait for first event to be processed (or timeout)
		deadline := time.Now().Add(2 * time.Second)
		for listener.received < 1 {
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}

		// Cancel before second line
		cancel()

		// Write second line to unblock scanner
		pw.Write([]byte("{}\n"))
	}()

	err := obs.StartReady(ctx, func() {})
	if err != nil {
		t.Fatal(err)
	}

	// Only first event should be processed
	if listener.received != 1 {
		t.Fatalf("expected 1 event (before cancel), got %d", listener.received)
	}
}

func TestListenerError_RemovesListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	log := slog.New(&triggerHandler{
		Handler:   logger.SlogNopHandler,
		trigger:   "Finished synthetic event replay",
		onTrigger: cancel,
	})

	reader := strings.NewReader("{}\n{}\n")
	obs := synthetic.NewReadingObserver(reader, &testCodec{}, log)

	good := &testListener{}
	bad := &testListener{notifyErr: errors.New("fail")}
	obs.AddListener(good)
	obs.AddListener(bad)

	if err := obs.StartReady(ctx, func() {}); err != nil {
		t.Fatal(err)
	}

	if good.received != 2 {
		t.Fatalf("expected good listener to receive 2 events, got %d", good.received)
	}

	if !bad.closed {
		t.Error("bad listener should be closed after error")
	}
}

func TestAddRemoveListener(t *testing.T) {
	obs := synthetic.NewReadingObserver(
		strings.NewReader(""),
		&testCodec{},
		nopLog,
	)

	listener := &testListener{}
	obs.AddListener(listener)
	obs.RemoveListener(listener)

	if !listener.closed {
		t.Error("listener should be closed on remove")
	}
}

func TestRemoveListener_CloseError(t *testing.T) {
	obs := synthetic.NewReadingObserver(
		strings.NewReader(""),
		&testCodec{},
		nopLog,
	)

	listener := &testListener{closeErr: errors.New("close failed")}
	obs.AddListener(listener)
	obs.RemoveListener(listener)

	if !listener.closed {
		t.Error("listener should be closed even on error")
	}
}

func TestStartReady_UnmarshalError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	log := slog.New(&triggerHandler{
		Handler:   logger.SlogNopHandler,
		trigger:   "Finished",
		onTrigger: cancel,
	})

	reader := strings.NewReader("{}\n{}\n")
	obs := synthetic.NewReadingObserver(reader, &unmarshalErrorCodec{}, log)

	listener := &testListener{}
	obs.AddListener(listener)

	if err := obs.StartReady(ctx, func() {}); err != nil {
		t.Fatal(err)
	}

	// No events delivered due to unmarshal errors
	if listener.received != 0 {
		t.Fatalf("expected 0 events, got %d", listener.received)
	}
}

func TestStartReady_NotMessageType(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	log := slog.New(&triggerHandler{
		Handler:   logger.SlogNopHandler,
		trigger:   "Finished",
		onTrigger: cancel,
	})

	reader := strings.NewReader("{}\n{}\n")
	obs := synthetic.NewReadingObserver(reader, &notMessageCodec{}, log)

	listener := &testListener{}
	obs.AddListener(listener)

	if err := obs.StartReady(ctx, func() {}); err != nil {
		t.Fatal(err)
	}

	// No events delivered because codec returns non-Message type
	if listener.received != 0 {
		t.Fatalf("expected 0 events, got %d", listener.received)
	}
}
