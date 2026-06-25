// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/sensors/program"
)

func TestCleanupProgsAndMapsTracksMapLifecycle(t *testing.T) {
	// Isolate the process-global registry for this lifecycle test.
	allProgramsAndMapsMutex.Lock()
	savedPrograms := allPrograms
	savedMaps := allMaps
	allPrograms = nil
	allMaps = nil
	allProgramsAndMapsMutex.Unlock()
	t.Cleanup(func() {
		allProgramsAndMapsMutex.Lock()
		allPrograms = savedPrograms
		allMaps = savedMaps
		allProgramsAndMapsMutex.Unlock()
	})

	// Map-only sensors use an ELF program as a map-spec template without ever
	// loading that program. The map's own pin state is therefore the source of
	// truth for whether it remains registered.
	template := &program.Program{}
	policyMap := &program.Map{
		Name:     "map-only-policy-owner",
		Prog:     template,
		PinState: program.Idle(),
	}
	policyMap.PinState.RefInc()
	addProgsAndMaps(nil, []*program.Map{policyMap})

	cleanupProgsAndMaps()
	require.Equal(t, []*program.Map{policyMap}, AllMaps(),
		"a loaded map must remain registered even when its template program is idle")

	policyMap.PinState.RefDec()
	cleanupProgsAndMaps()
	require.Empty(t, AllMaps(), "an unloaded map must be removed from the registry")
}
