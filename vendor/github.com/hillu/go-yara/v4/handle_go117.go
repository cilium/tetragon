//+build go1.17

// This variant contains a trivial wrapper around "runtime/cgo".Handle.

package yara

import "runtime/cgo"

type cgoHandle cgo.Handle

func (h cgoHandle) Value() interface{} { return cgo.Handle(h).Value() }

func (h cgoHandle) Delete() { cgo.Handle(h).Delete() }

func cgoNewHandle(v interface{}) cgoHandle { return cgoHandle(cgo.NewHandle(v)) }
