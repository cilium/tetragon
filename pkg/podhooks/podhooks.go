// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package podhooks

import (
	"k8s.io/client-go/tools/cache"
)

var (
	allCallbacks  = []Callbacks{}
	allowRegister = true
)

type Callbacks struct {
	PodCallbacks func(podInformer cache.SharedIndexInformer)
}

// RegisterCallbacksAtInit registers callbacks.
// Must be called before InstallHooks and callers need to be serialized externally.
func RegisterCallbacksAtInit(cbs Callbacks) {
	if !allowRegister {
		panic("podhooks.RegisterCallbacksAtInit must be called before podhooks.InstallHooks()")
	}
	allCallbacks = append(allCallbacks, cbs)
}

// InstallHooks executes all registered callbacks
func InstallHooks(podInformer cache.SharedIndexInformer) {
	allowRegister = false
	for _, cbs := range allCallbacks {
		if fn := cbs.PodCallbacks; fn != nil {
			fn(podInformer)
		}
	}
}
