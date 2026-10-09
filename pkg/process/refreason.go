// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"slices"
	"strconv"
	"sync"
)

type RefReason uint32

const (
	RefProcess RefReason = iota
	RefParent
	RefAncestor
)

var refReasons = struct {
	sync.RWMutex
	names []string
}{names: []string{"process", "parent", "ancestor"}}

func NewRefReason(name string) RefReason {
	refReasons.Lock()
	defer refReasons.Unlock()

	if slices.Contains(refReasons.names, name) {
		panic("process: duplicate ref reason: " + name)
	}

	refReasons.names = append(refReasons.names, name)

	return RefReason(len(refReasons.names) - 1)
}

func refReasonName(r RefReason) string {
	refReasons.RLock()
	defer refReasons.RUnlock()

	if int(r) < len(refReasons.names) {
		return refReasons.names[r]
	}

	return "reason-" + strconv.FormatUint(uint64(r), 10)
}
