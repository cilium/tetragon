// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/testutils"
)

func Test_ioReaderClient_GetEvents(t *testing.T) {
	events, err := os.Open(testutils.RepoRootPath("testdata/events.json"))
	require.NoError(t, err)
	client := newIOReaderClient(events, false)
	getEventsClient, err := client.GetEvents(context.Background(), &tetragon.GetEventsRequest{})
	require.NoError(t, err)
	for range 3 {
		_, err := getEventsClient.Recv()
		require.NoError(t, err)
	}
	_, err = getEventsClient.Recv()
	require.ErrorIs(t, err, io.EOF)
}
