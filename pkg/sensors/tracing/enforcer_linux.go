// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/metrics/enforcermetrics"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func enforcerMapsUser(load *program.Program) []*program.Map {
	edm := program.MapUserPolicy(EnforcerDataMapName, load)
	edm.SetMaxEntries(enforcerMapMaxEntries)
	return []*program.Map{
		edm,
		program.MapUserPolicy(enforcermetrics.EnforcerMissedMapName, load),
	}
}
