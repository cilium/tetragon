// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
)

func updateMapSize(mapLinkStats *ebpf.Map, maxEntries int, name string) {
	var values []int64
	if err := mapLinkStats.Lookup(int32(0), &values); err != nil {
		return
	}

	sum := int64(0)
	for _, n := range values {
		sum += n
	}

	mapmetrics.MapSizeSet(name, maxEntries, float64(sum))
}

func updateMapErrors(mapLinkStats *ebpf.Map, name string) {
	var values []int64
	if err := mapLinkStats.Lookup(int32(1), &values); err != nil {
		return
	}

	sum := int64(0)
	for _, n := range values {
		sum += n
	}

	mapmetrics.MapErrorSet(name, float64(sum))
}

func updateMapMetric(name string) {
	pin := filepath.Join(option.Config.MapDir, name)
	pinStats := pin + "_stats"

	mapLinkStats, err := ebpf.LoadPinnedMap(pinStats, nil)
	if err != nil {
		return
	}
	defer mapLinkStats.Close()
	mapLink, err := ebpf.LoadPinnedMap(pin, nil)
	if err != nil {
		return
	}
	defer mapLink.Close()

	updateMapSize(mapLinkStats, int(mapLink.MaxEntries()), name)
	updateMapErrors(mapLinkStats, name)
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
