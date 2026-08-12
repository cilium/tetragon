// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRetryPolicyDisablesRetriesAtZero(t *testing.T) {
	require.JSONEq(t, `{}`, RetryPolicy(0, ""))
}

func TestNewClientWithZeroRetries(t *testing.T) {
	oldRetries := Retries
	oldTimeout := Timeout
	t.Cleanup(func() {
		Retries = oldRetries
		Timeout = oldTimeout
	})

	Retries = 0
	Timeout = time.Second
	c, err := NewClient(context.Background(), "passthrough:///unused", Timeout)
	require.NoError(t, err)
	c.Close()
}
