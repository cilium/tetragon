// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/javaapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/defaults"
	grpctracing "github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/process"
)

func javaRecord(t *testing.T) []byte {
	t.Helper()
	msg := javaapi.MsgJava{
		Common: processapi.MsgCommon{
			Op:    ops.MSG_OP_JAVA,
			Flags: processapi.MSG_COMMON_FLAG_PROCESS_NOT_FOUND,
			Size:  javaapi.MsgJavaSize,
			Ktime: 123456789,
		},
		ProcessKey: processapi.MsgExecveKey{Pid: 100, Ktime: 123456789},
		MethodID:   0x1234,
		TID:        101,
	}
	copy(msg.ClassName[:], "example/Foo")
	copy(msg.MethodName[:], "work")
	copy(msg.Descriptor[:], "(I)V")
	var data bytes.Buffer
	require.NoError(t, binary.Write(&data, binary.LittleEndian, &msg))
	return data.Bytes()
}

func TestHandleJava(t *testing.T) {
	require.NoError(t, process.InitCache(nil, 16, defaults.DefaultProcessCacheGCInterval))
	t.Cleanup(process.FreeCache)

	op, events, err := observer.HandlePerfData(javaRecord(t))
	require.Nil(t, err)
	require.Equal(t, byte(ops.MSG_OP_JAVA), op)
	require.Len(t, events, 1)

	msg := events[0].(*grpctracing.MsgJavaEvent)
	response := msg.HandleMessage()
	require.NotNil(t, response)
	ev := response.GetProcessJava()
	require.Equal(t, uint64(0x1234), ev.MethodId)
	require.Equal(t, "example/Foo", ev.ClassName)
	require.Equal(t, "work", ev.MethodName)
	require.Equal(t, "(I)V", ev.Descriptor_)
	require.Equal(t, uint32(100), ev.Process.GetPid().GetValue())
	require.Nil(t, ev.Process.Tid)
	require.Equal(t, "unknown", ev.Process.Flags)
	require.NotNil(t, response.Time)
}

func TestHandleJavaRejectsMalformedRecords(t *testing.T) {
	valid := javaRecord(t)
	for name, data := range map[string][]byte{
		"short": valid[:len(valid)-1],
		"long":  append(append([]byte{}, valid...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := observer.HandlePerfData(data)
			require.NotNil(t, err)
		})
	}

	badSize := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(badSize[4:8], javaapi.MsgJavaSize-1)
	_, _, err := observer.HandlePerfData(badSize)
	require.NotNil(t, err)
}
