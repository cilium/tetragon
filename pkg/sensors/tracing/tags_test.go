// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPolicyTags(t *testing.T) {
	input := []string{""}
	_, err := getPolicyTags(input)
	require.Error(t, err)

	// short tag
	input = []string{"a"}
	_, err = getPolicyTags(input)
	require.Error(t, err)

	input = []string{"observability.filesystem"}
	tags, err := getPolicyTags(input)
	require.NoError(t, err)
	require.Len(t, tags, 1)

	input = []string{"observability.filesystem", "", "CVES"}
	_, err = getPolicyTags(input)
	require.Error(t, err)

	input = []string{"observability.filesystem", "CVES", "aa"}
	tags, err = getPolicyTags(input)
	require.NoError(t, err)
	require.Len(t, tags, 3)

	input = []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17"}
	_, err = getPolicyTags(input)
	require.Error(t, err)
}
