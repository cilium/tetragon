// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaagent

import (
	"encoding/binary"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// The agent counts the records it dropped in the ring header, check the
// session moves only the new ones to the lost metric.
func TestSessionAccountLost(t *testing.T) {
	ring, err := NewRing(minRingDataSize)
	require.NoError(t, err)
	defer ring.Close()

	lost := func(typ string) float64 {
		return testutil.ToFloat64(ringLost.WithLabelValues(typ))
	}
	entries, defs := lost(lostEntry), lost(lostDefinition)

	c := &session{}
	c.accountLost(ring)
	require.InDelta(t, entries, lost(lostEntry), 0)
	require.InDelta(t, defs, lost(lostDefinition), 0)

	binary.LittleEndian.PutUint64(ring.data[ringOffDropped:], 5)
	binary.LittleEndian.PutUint64(ring.data[ringOffDroppedDefs:], 2)
	c.accountLost(ring)
	c.accountLost(ring)
	require.InDelta(t, entries+5, lost(lostEntry), 0)
	require.InDelta(t, defs+2, lost(lostDefinition), 0)

	binary.LittleEndian.PutUint64(ring.data[ringOffDropped:], 8)
	c.accountLost(ring)
	require.InDelta(t, entries+8, lost(lostEntry), 0)
	require.InDelta(t, defs+2, lost(lostDefinition), 0)
}
