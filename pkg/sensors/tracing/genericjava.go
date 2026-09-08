// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/tetragon/pkg/api/javaapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	grpctracing "github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/observer"
)

func handleJava(r *bytes.Reader) ([]observer.Event, error) {
	var msg javaapi.MsgJava
	if r.Len() != int(javaapi.MsgJavaSize) {
		return nil, fmt.Errorf("invalid Java record size: got %d, want %d", r.Len(), javaapi.MsgJavaSize)
	}
	if err := binary.Read(r, binary.LittleEndian, &msg); err != nil {
		return nil, fmt.Errorf("decode Java record: %w", err)
	}
	if msg.Common.Op != ops.MSG_OP_JAVA {
		return nil, fmt.Errorf("invalid Java opcode: %d", msg.Common.Op)
	}
	if msg.Common.Size != javaapi.MsgJavaSize {
		return nil, fmt.Errorf("invalid Java common size: got %d, want %d", msg.Common.Size, javaapi.MsgJavaSize)
	}
	return []observer.Event{&grpctracing.MsgJavaEvent{Msg: &msg}}, nil
}

func init() {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_JAVA, handleJava)
}
