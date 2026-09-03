// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package javaapi

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestMsgJavaLayout(t *testing.T) {
	var msg MsgJava
	require.Equal(t, uintptr(432), unsafe.Sizeof(msg))
	require.Equal(t, uintptr(0), unsafe.Offsetof(msg.Common))
	require.Equal(t, uintptr(16), unsafe.Offsetof(msg.ProcessKey))
	require.Equal(t, uintptr(32), unsafe.Offsetof(msg.MethodID))
	require.Equal(t, uintptr(40), unsafe.Offsetof(msg.TID))
	require.Equal(t, uintptr(44), unsafe.Offsetof(msg.ClassName))
	require.Equal(t, uintptr(172), unsafe.Offsetof(msg.MethodName))
	require.Equal(t, uintptr(300), unsafe.Offsetof(msg.Descriptor))
	require.Equal(t, uintptr(428), unsafe.Offsetof(msg.Pad))
}

func TestMethodID(t *testing.T) {
	require.Equal(t, uint64(0xf296cbc2a8e1eeeb), MethodID("example/Foo", "work", "(I)V"))
	require.NotEqual(t,
		MethodID("example/Foo", "work", "(I)V"),
		MethodID("example/Foo", "work", "(J)V"),
	)
}
