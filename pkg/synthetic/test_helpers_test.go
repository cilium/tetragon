// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/synthetic"
)

// nopLog is a logger that discards all output.
var nopLog = slog.New(logger.SlogNopHandler)

func init() {
	synthetic.RegisterType((*testMessage)(nil))
}

// testMessage implements notify.Message for testing.
type testMessage struct{}

func (testMessage) HandleMessage() *tetragon.GetEventsResponse { return nil }
func (testMessage) RetryInternal(notify.Event, uint64) (*process.ProcessInternal, error) {
	return nil, nil
}
func (testMessage) Retry(*process.ProcessInternal, notify.Event) error { return nil }
func (testMessage) Notify() bool                                       { return true }
func (m testMessage) Cast(any) notify.Message                          { return m }

// testCodec is a simple codec for testing.
type testCodec struct{}

func (testCodec) Marshal(any) ([]byte, error)   { return []byte("{}"), nil }
func (testCodec) Unmarshal([]byte) (any, error) { return &testMessage{}, nil }

// marshalErrorCodec returns error on Marshal.
type marshalErrorCodec struct{}

func (marshalErrorCodec) Marshal(any) ([]byte, error)   { return nil, errors.New("marshal error") }
func (marshalErrorCodec) Unmarshal([]byte) (any, error) { return nil, nil }

// unmarshalErrorCodec returns error on Unmarshal.
type unmarshalErrorCodec struct{}

func (unmarshalErrorCodec) Marshal(any) ([]byte, error)   { return nil, nil }
func (unmarshalErrorCodec) Unmarshal([]byte) (any, error) { return nil, errors.New("unmarshal error") }

// notMessageCodec returns something that doesn't implement notify.Message.
type notMessageCodec struct{}

func (notMessageCodec) Marshal(any) ([]byte, error)   { return nil, nil }
func (notMessageCodec) Unmarshal([]byte) (any, error) { return "not a message", nil }

// mismatchCodec returns different object on Unmarshal to trigger mismatch.
type mismatchCodec struct{}

func (mismatchCodec) Marshal(any) ([]byte, error)   { return []byte("{}"), nil }
func (mismatchCodec) Unmarshal([]byte) (any, error) { return &testCodec{}, nil }

// testListener implements observertypes.Listener for testing.
type testListener struct {
	received  int
	notifyErr error
	closeErr  error
	closed    bool
}

func (l *testListener) Notify(notify.Message) error {
	l.received++
	return l.notifyErr
}

func (l *testListener) Close() error {
	l.closed = true
	return l.closeErr
}

// triggerHandler wraps slog.Handler and calls onTrigger when msg contains trigger.
type triggerHandler struct {
	slog.Handler
	trigger   string
	onTrigger func()
}

func (triggerHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h triggerHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.trigger) {
		h.onTrigger()
	}
	return nil
}

// warnHandler captures Warn calls for assertions.
type warnHandler struct {
	slog.Handler
	warnCalled  bool
	wantMessage string
	gotMessage  bool
}

func (warnHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *warnHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn {
		h.warnCalled = true
		if h.wantMessage != "" && strings.Contains(r.Message, h.wantMessage) {
			h.gotMessage = true
		}
	}
	return nil
}

// errorWriter returns error on Write.
type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write error") }

// mockDelegate implements observertypes.Listener for testing delegate.
type mockDelegate struct{}

func (mockDelegate) Notify(notify.Message) error { return errors.New("delegate notify") }
func (mockDelegate) Close() error                { return errors.New("delegate close") }
