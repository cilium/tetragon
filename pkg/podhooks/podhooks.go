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

// RegisterCallbacksAtInit registers callbacks (should be called at init())
func RegisterCallbacksAtInit(cbs Callbacks) {
	if !allowRegister {
		panic("podhooks.RegisterCallbacksAtInit must be called only in init()")
	}
	allCallbacks = append(allCallbacks, cbs)
}

// runHooks executes all registered callbacks
func InstallHooks(podInformer cache.SharedIndexInformer) {
	allowRegister = false
	for _, cbs := range allCallbacks {
		if fn := cbs.PodCallbacks; fn != nil {
			fn(podInformer)
		}
	}
}
