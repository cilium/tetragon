// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package calltraceapi

type StackAddr struct {
	Addr   uint64
	Symbol string
}

type MsgCalltrace struct {
	Stack [16]uint64
	Ret   int32
}
