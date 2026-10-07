// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"strconv"
	"testing"
)

var (
	benchReasons = func() []RefReason {
		r := []RefReason{RefProcess, RefParent, RefAncestor}
		for len(r) < 70 {
			r = append(r, NewRefReason("bench-"+strconv.Itoa(len(r))))
		}
		return r
	}()
	benchCards = []int{1, 3, 8, 16, 70}
	benchOps   *refcntOps
)

func BenchmarkRefcntOpsBuild(b *testing.B) {
	for _, k := range benchCards {
		b.Run(strconv.Itoa(k), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				o := &refcntOps{}
				for _, r := range benchReasons[:k] {
					o.inc(r)
				}
				benchOps = o
			}
		})
	}
}

func BenchmarkRefcntOpsUpdate(b *testing.B) {
	for _, k := range benchCards {
		b.Run(strconv.Itoa(k), func(b *testing.B) {
			o := &refcntOps{}
			for _, r := range benchReasons[:k] {
				o.inc(r)
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				o.inc(benchReasons[i])
				if i++; i == k {
					i = 0
				}
			}
		})
	}
}
