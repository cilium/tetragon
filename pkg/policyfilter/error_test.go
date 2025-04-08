// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorLabel(t *testing.T) {
	var err error = &podNamespaceConflictError{PodID{}, "foo", "lala"}
	require.Equal(t, "", ErrorLabel(nil))
	require.Equal(t, "pod-namespace-conflict", ErrorLabel(err))
}
