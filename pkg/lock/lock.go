// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

// RWMutex is equivalent to sync.RWMutex but applies deadlock detection if the
// built tag "lockdebug" is set
type RWMutex struct {
	internalRWMutex
}

// Mutex is equivalent to sync.Mutex but applies deadlock detection if the
// built tag "lockdebug" is set
type Mutex struct {
	internalMutex
}
