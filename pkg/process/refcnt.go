// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import "sync"

type refcntEntry struct {
	reason RefReason
	inc    int32
	dec    int32
}

type refcntOps struct {
	mu   sync.Mutex
	data []refcntEntry
}

func (o *refcntOps) find(reason RefReason) *refcntEntry {
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
	o.find(reason).inc++
	o.mu.Unlock()
}

func (o *refcntOps) dec(reason RefReason) {
	o.mu.Lock()
	o.find(reason).dec++
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
