// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPolicyMessage(t *testing.T) {
	msg, err := getPolicyMessage("")
	require.Empty(t, msg)
	require.Equal(t, err, ErrMsgSyntaxEmpty)

	msg, err = getPolicyMessage("a")
	require.Empty(t, msg)
	require.Equal(t, err, ErrMsgSyntaxShort)

	msg, err = getPolicyMessage("test")
	require.NoError(t, err)
	require.Equal(t, "test", msg)

	msg, err = getPolicyMessage(strings.Repeat("a", TpMaxMessageLen+1))
	require.Equal(t, err, ErrMsgSyntaxLong)
	require.Len(t, msg, TpMaxMessageLen)
}
