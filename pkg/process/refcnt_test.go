// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testReasonA = NewRefReason("test-a")
	testReasonB = NewRefReason("test-b")
	testReasonC = NewRefReason("test-c")
)

func TestRefcntOpsBuiltin(t *testing.T) {
	var o refcntOps
	assert.Empty(t, o.toMap())

	o.inc(RefProcess)
	assert.Equal(t, map[string]int32{"process++": 1}, o.toMap())

	o.inc(RefProcess)
	o.dec(RefProcess)
	o.inc(RefParent)
	o.dec(RefAncestor)
	assert.Equal(t, map[string]int32{
		"process++":  2,
		"process--":  1,
		"parent++":   1,
		"ancestor--": 1,
	}, o.toMap())
}

func TestRefcntOpsCustom(t *testing.T) {
	var o refcntOps
	o.inc(testReasonA)
	o.inc(testReasonA)
	o.dec(testReasonB)
	o.inc(RefProcess)
	o.inc(testReasonC)
	o.dec(testReasonC)
	assert.Equal(t, map[string]int32{
		"test-a++":  2,
		"test-b--":  1,
		"process++": 1,
		"test-c++":  1,
		"test-c--":  1,
	}, o.toMap())
}

func TestRefcntOpsGrowthPreservesValues(t *testing.T) {
	var o refcntOps
	want := map[string]int32{}
	for i := range 40 {
		r := RefReason(1000 + i)
		for range i + 1 {
			o.inc(r)
		}
		want[refReasonName(r)+"++"] = int32(i + 1)
		o.inc(testReasonA)
		want["test-a++"]++
	}
	assert.Equal(t, want, o.toMap())
}

func TestRefcntOpsHighReason(t *testing.T) {
	high := RefReason(1 << 30)
	touch := func(r RefReason) float64 {
		return testing.AllocsPerRun(100, func() {
			var o refcntOps
			o.inc(r)
		})
	}
	assert.InDelta(t, touch(testReasonA), touch(high), 0.5)

	var o refcntOps
	o.inc(high)
	o.dec(high)
	assert.Equal(t, map[string]int32{"reason-1073741824++": 1, "reason-1073741824--": 1}, o.toMap())
}

func TestRefcntOpsConcurrent(t *testing.T) {
	var o refcntOps
	reasons := []RefReason{RefProcess, RefParent, RefAncestor, testReasonA, testReasonB, testReasonC, RefReason(5000)}
	const goroutines, iterations = 16, 1000

	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for i := range iterations {
				r := reasons[i%len(reasons)]
				o.inc(r)
				o.dec(r)
			}
		})
	}
	wg.Go(func() {
		for range 100 {
			_ = o.toMap()
		}
	})
	wg.Wait()

	got := o.toMap()
	assert.Len(t, got, 2*len(reasons))
	var inc, dec int32
	for k, v := range got {
		if strings.HasSuffix(k, "++") {
			inc += v
		} else {
			dec += v
		}
	}
	assert.Equal(t, int32(goroutines*iterations), inc)
	assert.Equal(t, int32(goroutines*iterations), dec)
}

func TestNewRefReasonDuplicate(t *testing.T) {
	assert.Panics(t, func() { NewRefReason("process") })
	assert.Panics(t, func() { NewRefReason("test-a") })
}

func TestRefcntOpsDumpViaProcess(t *testing.T) {
	pi := &ProcessInternal{}
	pi.refcntOps.inc(RefProcess)
	pi.refcntOps.inc(testReasonA)
	pi.refcntOps.dec(testReasonA)
	assert.Equal(t, map[string]int32{"process++": 1, "test-a++": 1, "test-a--": 1}, pi.refcntOps.toMap())
}
