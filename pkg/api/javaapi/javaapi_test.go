// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package javaapi

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

func TestMsgJavaLayout(t *testing.T) {
	var msg MsgJava
	require.Equal(t, uintptr(432), unsafe.Sizeof(msg))
	require.Equal(t, uintptr(16), unsafe.Offsetof(msg.ProcessKey))
	require.Equal(t, uintptr(32), unsafe.Offsetof(msg.MethodID))
	require.Equal(t, uintptr(40), unsafe.Offsetof(msg.TID))
	require.Equal(t, uintptr(44), unsafe.Offsetof(msg.ClassName))
	require.Equal(t, uintptr(172), unsafe.Offsetof(msg.MethodName))
	require.Equal(t, uintptr(300), unsafe.Offsetof(msg.Descriptor))
}

func TestMethodID(t *testing.T) {
	require.Equal(t, uint64(0xf296cbc2a8e1eeeb), MethodID("example/Foo", "work", "(I)V"))
	require.NotEqual(t, MethodID("example/Foo", "work", "(I)V"), MethodID("example/Foo", "work", "(J)V"))
}

func TestPreparePacketFillsProcessKeyKtime(t *testing.T) {
	msg := MsgJava{Common: processapi.MsgCommon{Op: ops.MSG_OP_JAVA, Size: MsgJavaSize, Ktime: 1234}, ProcessKey: processapi.MsgExecveKey{Pid: 1, Ktime: 99}}
	var data bytes.Buffer
	require.NoError(t, binary.Write(&data, binary.LittleEndian, &msg))
	require.NoError(t, PreparePacket(data.Bytes()))
	require.Equal(t, uint32(1), binary.LittleEndian.Uint32(data.Bytes()[16:20]), "self-reported PID is left untouched")
	require.Equal(t, uint64(1234), binary.LittleEndian.Uint64(data.Bytes()[24:32]), "ProcessKey.Ktime is copied from Common.Ktime")
}

func TestPreparePacketRejectsInvalidUTF8(t *testing.T) {
	data := make([]byte, MsgJavaSize)
	data[0] = byte(ops.MSG_OP_JAVA)
	binary.LittleEndian.PutUint32(data[4:8], MsgJavaSize)
	data[44] = 0xff
	require.Error(t, PreparePacket(data))
}
