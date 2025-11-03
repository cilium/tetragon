// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventhandler

import (
	"github.com/cilium/tetragon/pkg/observer"
)

type Handler func([]observer.Event, error) ([]observer.Event, error)

// CustomEventhandler allows components to define their custom event handling.
// This is intended for policies to:
//   - map events / and errors from tracing sensors (e.g., kprobe or tracepoints)
//   - generate custom metrics
//
// Other use-cases might be served from this as well
type HasCustomHandler interface {
	Handler() Handler
}

func GetCustomEventhandler(obj any) Handler {
	if ceh, ok := obj.(HasCustomHandler); ok {
		return ceh.Handler()
	}
	return nil
}
