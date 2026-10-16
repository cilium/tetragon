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

type refcntEntry struct {
	reason RefReason
	inc    int32
	dec    int32
}

type refcntOps struct {
	mu   sync.Mutex
	data []refcntEntry
}

func (o *refcntOps) findOrCreate(reason RefReason) *refcntEntry {
	for i := range o.data {
		if o.data[i].reason == reason {
			return &o.data[i]
		}
	}

	o.data = append(o.data, refcntEntry{reason: reason})

	return &o.data[len(o.data)-1]
}

func (o *refcntOps) inc(reason RefReason) {
	o.mu.Lock()
	o.findOrCreate(reason).inc++
	o.mu.Unlock()
}

func (o *refcntOps) dec(reason RefReason) {
	o.mu.Lock()
	o.findOrCreate(reason).dec++
	o.mu.Unlock()
}

func (o *refcntOps) toMap() map[string]int32 {
	o.mu.Lock()
	defer o.mu.Unlock()

	m := make(map[string]int32, 2*len(o.data))

	for _, e := range o.data {
		name := refReasonName(e.reason)

		if e.inc != 0 {
			m[name+"++"] = e.inc
		}
		if e.dec != 0 {
			m[name+"--"] = e.dec
		}
	}

	return m
}
