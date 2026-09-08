// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package javaapi defines the fixed wire format shared by the Java producer,
// the BPF bridge, and the Go observer.
package javaapi

import (
	"hash/fnv"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/processapi"
)

// MethodID returns the deterministic ID used by the Java agent. Each UTF-8
// component is separated by one NUL byte before applying 64-bit FNV-1a.
func MethodID(className, methodName, descriptor string) uint64 {
	hash := fnv.New64a()
	for _, value := range []string{className, methodName, descriptor} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hash.Sum64()
}

const (
	StringLength = 128
	MsgJavaSize  = uint32(432)
)

// MsgJava is copied unchanged from the user ring buffer to tg_rb_events.
// Keep this layout synchronized with struct msg_java in bpf/lib/java.h and
// UserRingBuffer.java.
type MsgJava struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	MethodID   uint64
	TID        uint32
	ClassName  [StringLength]byte
	MethodName [StringLength]byte
	Descriptor [StringLength]byte
	Pad        [4]byte
}

func init() {
	if unsafe.Sizeof(MsgJava{}) != uintptr(MsgJavaSize) {
		panic("java wire record has unexpected size")
	}
}
