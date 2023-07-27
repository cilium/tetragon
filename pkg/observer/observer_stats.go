// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
)

type statKey struct {
	Key int32
}

type statValue struct {
	Value []int64 // kernel rounds up to 64bits so pretend its a 64bit here
}

func (k *statKey) String() string            { return fmt.Sprintf("key=%d", k.Key) }
func (k *statKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *statKey) NewValue() bpf.MapValue {
	return &statValue{
		Value: make([]int64, bpf.GetNumPossibleCPUs()),
	}
}
func (k *statKey) DeepCopyMapKey() bpf.MapKey { return &statKey{k.Key} }

func (s *statValue) String() string {
	return fmt.Sprintf("%v", s.Value)
}
func (s *statValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&s.Value[0])
}
func (s *statValue) DeepCopyMapValue() bpf.MapValue {
	v := &statValue{
		Value: make([]int64, len(s.Value)),
	}
	copy(v.Value, s.Value)
	return v
}

func updateMapMetric(name string) {
	pin := filepath.Join(option.Config.MapDir, name)
	pinStats := pin + "_stats"

	mapLinkStats, err := bpf.OpenMap(pinStats)
	if err != nil {
		return
	}
	defer mapLinkStats.Close()
	mapLink, err := bpf.OpenMap(pin)
	if err != nil {
		return
	}
	defer mapLink.Close()

	zeroKey := &statKey{}
	value, err := mapLinkStats.Lookup(zeroKey)
	if err != nil {
		return
	}

	v, ok := value.DeepCopyMapValue().(*statValue)
	if !ok {
		return
	}

	sum := int64(0)
	for cpu := int(0); cpu < runtime.NumCPU(); cpu++ {
		sum += v.Value[cpu]
	}
	mapmetrics.MapSizeSet(name, int(mapLink.MapInfo.MaxEntries), float64(sum))
}

func (k *Observer) startUpdateMapMetrics() {
	update := func() {
		for _, m := range sensors.AllMaps {
			updateMapMetric(m.Name)
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				update()
			}
		}
	}()
}
