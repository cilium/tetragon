// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mbset

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveIDReleasesSlotWhenUpdaterNil(t *testing.T) {
	s, err := newState()
	require.NoError(t, err)

	id, err := s.AllocID()
	require.NoError(t, err)

	require.NoError(t, s.RemoveID(id, nil))

	// Slot must be reusable; otherwise followChildren IDs leak under the 64-bit cap.
	id2, err := s.AllocID()
	require.NoError(t, err)
	require.Equal(t, id, id2)
}
