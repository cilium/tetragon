//go:build !go1.17 && go1.15
// +build !go1.17,go1.15

// This variant contains a backport of go 1.18's "runtime/cgo".Handle.

package yara

import (
	"sync"
	"sync/atomic"
)

type cgoHandle uintptr

func cgoNewHandle(v interface{}) cgoHandle {
	h := atomic.AddUintptr(&handleIdx, 1)
	if h == 0 {
		panic("cgoNewHandle: ran out of handle space")
	}

	handles.Store(h, v)
	return cgoHandle(h)
}

func (h cgoHandle) Value() interface{} {
	v, ok := handles.Load(uintptr(h))
	if !ok {
		panic("cgoHandle: misuse of an invalid Handle")
	}
	return v
}

func (h cgoHandle) Delete() {
	_, ok := handles.LoadAndDelete(uintptr(h))
	if !ok {
		panic("cgoHandle: misuse of an invalid Handle")
	}
}

var (
	handles   = sync.Map{}
	handleIdx uintptr
)
