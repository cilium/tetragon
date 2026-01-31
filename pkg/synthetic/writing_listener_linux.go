// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// writing_listener.go implements WritingListener that writes Tetragon events to a file
// for later replay and debugging. Supports optional roundtrip verification.

package synthetic

import (
	"encoding/json"
	"io"
	"reflect"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observertypes"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

// WritingListener implements observertypes.Listener and writes all received events
// to a JSON lines file for later replay.
type WritingListener struct {
	writer          io.Writer
	codec           Codec
	log             logger.FieldLogger
	verifyRoundtrip bool
	delegate        observertypes.Listener
}

// Option configures WritingListener.
type Option func(*WritingListener)

// NewWritingListener creates a new WritingListener with the given writer, codec and logger.
func NewWritingListener(writer io.Writer, codec Codec, log logger.FieldLogger, opts ...Option) *WritingListener {
	l := &WritingListener{
		writer: writer,
		codec:  codec,
		log:    log,
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// Notify implements observertypes.Listener.Notify.
// It serializes the event to JSON and writes it to the file.
func (l *WritingListener) Notify(msg notify.Message) error {
	logBytes, err := l.codec.Marshal(msg)
	if err != nil {
		l.log.Warn("Failed to marshal event for synthetic logging", "error", err)
		return err
	}

	if l.verifyRoundtrip {
		l.verifyRoundtripEquality(msg, logBytes)
	}

	if l.writer != nil {
		_, err = l.writer.Write(append(logBytes, '\n'))
		if err != nil {
			l.log.Warn("Failed to write synthetic event", "error", err)
			return err
		}
	}

	if l.delegate != nil {
		return l.delegate.Notify(msg)
	}
	return nil
}

// Close implements observertypes.Listener.Close.
func (l *WritingListener) Close() error {
	if l.delegate != nil {
		return l.delegate.Close()
	}
	return nil
}

// WithVerifyRoundtrip enables roundtrip verification.
func WithVerifyRoundtrip(enabled bool) Option {
	return func(l *WritingListener) {
		l.verifyRoundtrip = enabled
	}
}

// WithDelegate sets the delegate listener that receives events after recording.
func WithDelegate(delegate observertypes.Listener) Option {
	return func(l *WritingListener) {
		l.delegate = delegate
	}
}

// verifyRoundtripEquality unmarshals serialized data and compares with original.
func (l *WritingListener) verifyRoundtripEquality(original notify.Message, data []byte) {
	reconstructed, err := l.codec.Unmarshal(data)
	if err != nil {
		l.log.Warn("Roundtrip verification: unmarshal failed",
			"error", err,
			"type", reflect.TypeOf(original).String())
		return
	}

	if !reflect.DeepEqual(original, reconstructed) {
		origJSON, _ := json.Marshal(original)
		reconJSON, _ := json.Marshal(reconstructed)
		l.log.Warn("Roundtrip verification: mismatch detected",
			"type", reflect.TypeOf(original).String(),
			"original", string(origJSON),
			"reconstructed", string(reconJSON))
	}
}
