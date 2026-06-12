// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// TestSensor_TotalMemlock exercises the race between TracingPolicy
// load/unload (which mutates Program.loadedMapsInfo) and concurrent readers
// of Sensor.TotalMemlock (gRPC ListTracingPolicies). Prior to the fix,
// this triggered "fatal error: concurrent map iteration and map write" in
// maps.Copy. With the fix the field is guarded by Program.mapsMu and access
// goes through SetLoadedMapsInfo / CopyLoadedMapsInfo.
//
// Run with -race to lock the regression in:
//
//	go test -race ./pkg/sensors/ -run TestSensor_TotalMemlock
func TestSensor_TotalMemlock(_ *testing.T) {
	prog := &program.Program{}
	s := Sensor{Progs: []*program.Program{prog}}

	const goroutines = 8
	const iters = 5_000
	var wg sync.WaitGroup

	// Writers: simulate load/unload churn flipping the loadedMapsInfo map.
	for range goroutines {
		wg.Go(func() {
			for j := range iters {
				m := map[int]bpf.ExtendedMapInfo{
					j: {Memlock: 4096},
				}
				prog.SetLoadedMapsInfo(m)
				prog.SetLoadedMapsInfo(nil)
			}
		})
	}

	// Readers: simulate gRPC ListTracingPolicies polling.
	for range goroutines {
		wg.Go(func() {
			for range iters {
				_ = s.TotalMemlock()
			}
		})
	}

	wg.Wait()
}
