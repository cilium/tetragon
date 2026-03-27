// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/synthetic"
)

func TestNotify_Success(t *testing.T) {
	var buf bytes.Buffer
	listener := synthetic.NewWritingListener(&buf, synthetic.Serializer{}, nopLog)

	if err := listener.Notify(&testMessage{}); err != nil {
		t.Fatal(err)
	}

	want := `{"synthetic_type":"*synthetic_test.testMessage","synthetic_value":{}}` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNotify_MarshalError(t *testing.T) {
	var buf bytes.Buffer
	listener := synthetic.NewWritingListener(&buf, marshalErrorCodec{}, nopLog)

	if err := listener.Notify(&testMessage{}); err == nil {
		t.Error("expected error on marshal failure")
	}

	if buf.Len() != 0 {
		t.Error("no data should be written on marshal failure")
	}
}

func TestNotify_WriteError(t *testing.T) {
	listener := synthetic.NewWritingListener(errorWriter{}, synthetic.Serializer{}, nopLog)

	if err := listener.Notify(&testMessage{}); err == nil {
		t.Error("expected error on write failure")
	}
}

func TestNotify_WithVerifyRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	h := &warnHandler{Handler: logger.SlogNopHandler}
	listener := synthetic.NewWritingListener(
		&buf,
		synthetic.Serializer{},
		slog.New(h),
		synthetic.WithVerifyRoundtrip(true),
	)

	if err := listener.Notify(&testMessage{}); err != nil {
		t.Fatal(err)
	}

	if h.warnCalled {
		t.Error("expected no warnings on successful roundtrip")
	}
}

func TestNotify_VerifyRoundtrip_UnmarshalError(t *testing.T) {
	var buf bytes.Buffer
	h := &warnHandler{
		Handler:     logger.SlogNopHandler,
		wantMessage: "Roundtrip verification: unmarshal failed",
	}
	listener := synthetic.NewWritingListener(
		&buf,
		unmarshalErrorCodec{},
		slog.New(h),
		synthetic.WithVerifyRoundtrip(true),
	)

	if err := listener.Notify(&testMessage{}); err != nil {
		t.Fatal(err)
	}

	if !h.gotMessage {
		t.Error("expected unmarshal failed warning")
	}
}

func TestNotify_VerifyRoundtrip_Mismatch(t *testing.T) {
	var buf bytes.Buffer
	h := &warnHandler{
		Handler:     logger.SlogNopHandler,
		wantMessage: "Roundtrip verification: mismatch detected",
	}
	listener := synthetic.NewWritingListener(
		&buf,
		mismatchCodec{},
		slog.New(h),
		synthetic.WithVerifyRoundtrip(true),
	)

	if err := listener.Notify(&testMessage{}); err != nil {
		t.Fatal(err)
	}

	if !h.gotMessage {
		t.Error("expected mismatch warning")
	}
}

func TestNotify_WithDelegate(t *testing.T) {
	var buf bytes.Buffer
	listener := synthetic.NewWritingListener(
		&buf,
		synthetic.Serializer{},
		nopLog,
		synthetic.WithDelegate(mockDelegate{}),
	)

	err := listener.Notify(&testMessage{})
	if err == nil || err.Error() != "delegate notify" {
		t.Errorf("expected delegate notify error, got %v", err)
	}
}

func TestClose_Success(t *testing.T) {
	listener := synthetic.NewWritingListener(nil, synthetic.Serializer{}, nopLog)

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClose_WithDelegate(t *testing.T) {
	listener := synthetic.NewWritingListener(
		nil,
		synthetic.Serializer{},
		nopLog,
		synthetic.WithDelegate(mockDelegate{}),
	)

	err := listener.Close()
	if err == nil || err.Error() != "delegate close" {
		t.Errorf("expected delegate close error, got %v", err)
	}
}
