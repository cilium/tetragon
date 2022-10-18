// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

func Test_ioReaderClient_GetEvents(t *testing.T) {
	events, err := os.Open("testdata/events.json")
	assert.NoError(t, err)
	client := newIOReaderClient(events, false)
	getEventsClient, err := client.GetEvents(context.Background(), &tetragon.GetEventsRequest{})
	assert.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := getEventsClient.Recv()
		assert.NoError(t, err)
	}
	_, err = getEventsClient.Recv()
	assert.ErrorIs(t, err, io.EOF)
}
