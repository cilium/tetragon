// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"
)

const (
	// Max length of message field of a Tracing Policy
	TpMaxMessageLen = 256
	// Minimum length of message field ot a Tracing Policy
	// so it makes sense and we ensure it is not single
	// quoted character, we want double quoted string
	TpMinMessageLen = 2
)

var (
	ErrMsgSyntaxLong   = errors.New("message field is too long")
	ErrMsgSyntaxShort  = errors.New("message field is too short")
	ErrMsgSyntaxEmpty  = errors.New("message field is empty")
	ErrMsgSyntaxEscape = errors.New("message field escape failed")
)

// getPolicyMessage() Validates and escapes the passed message.
//
// Returns: On success the validated message of max length TpMaxMessageLen.
// On failures an error is set.
//
// If the message length is more than TpMaxMessageLen
// then the truncated message to TpMaxMessageLen with the error
// ErrMsgTooLong will be returned.
func getPolicyMessage(message string) (string, error) {
	if message == "" {
		return "", ErrMsgSyntaxEmpty
	}

	var err error
	msgLen := len(message)
	if msgLen < TpMinMessageLen {
		return "", ErrMsgSyntaxShort
	} else if msgLen > TpMaxMessageLen {
		msgLen = TpMaxMessageLen
		err = ErrMsgSyntaxLong
	}

	msg := fmt.Sprintf("%q", message[:msgLen])
	newLen := len(msg)
	if newLen <= msgLen || msg[0] != '"' || msg[newLen-1] != '"' {
		return "", ErrMsgSyntaxEscape
	}

	// Remove double quoted string so we pretty print it later in the events
	return msg[1 : newLen-1], err
}
