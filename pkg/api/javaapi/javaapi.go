// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package javaapi defines the fixed wire format shared by the Java producer
// and the Go observer.
package javaapi

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"unicode/utf8"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

// MethodID returns the deterministic ID used by the Java agent. Components
// are separated by one NUL byte before applying 64-bit FNV-1a.
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

// MsgJava is the fixed-size record stored in a shared-memory ring slot.
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

// PreparePacket validates a record's format and fills in the ProcessKey
// fields the Java agent doesn't set. The record's PID (written by the JVM
// itself) is trusted as-is: there is no control-socket peer to authenticate
// it against.
func PreparePacket(data []byte) error {
	if len(data) != int(MsgJavaSize) {
		return fmt.Errorf("invalid Java packet size: got %d, want %d", len(data), MsgJavaSize)
	}
	if data[0] != byte(ops.MSG_OP_JAVA) {
		return fmt.Errorf("invalid Java opcode: %d", data[0])
	}
	size := binary.LittleEndian.Uint32(data[4:8])
	if size != MsgJavaSize {
		return fmt.Errorf("invalid Java common size: %d", size)
	}
	for _, field := range [][]byte{data[44:172], data[172:300], data[300:428]} {
		end := len(field)
		for i, b := range field {
			if b == 0 {
				end = i
				break
			}
		}
		if !utf8.Valid(field[:end]) {
			return fmt.Errorf("invalid UTF-8 in Java packet")
		}
	}
	ktime := binary.LittleEndian.Uint64(data[8:16])
	binary.LittleEndian.PutUint64(data[24:32], ktime)
	data[1] &^= processapi.MSG_COMMON_FLAG_PROCESS_NOT_FOUND
	return nil
}

func init() {
	if unsafe.Sizeof(MsgJava{}) != uintptr(MsgJavaSize) {
		panic("java wire record has unexpected size")
	}
}
