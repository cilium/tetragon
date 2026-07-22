// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

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

func Test_ioReaderClient_GetEventsSkipsInvalidJSON(t *testing.T) {
	client := newIOReaderClient(strings.NewReader("not-json\n{\"process_exec\":{\"process\":{\"binary\":\"/usr/bin/netserver\"}}}\n"), false)
	getEventsClient, err := client.GetEvents(context.Background(), &tetragon.GetEventsRequest{})
	require.NoError(t, err)

	res, err := getEventsClient.Recv()
	require.NoError(t, err)
	require.NotNil(t, res.GetProcessExec())

	_, err = getEventsClient.Recv()
	require.ErrorIs(t, err, io.EOF)
}

func Test_ioReaderClient_GetEventsLargeJSONLine(t *testing.T) {
	want := bytes.Repeat([]byte{'a'}, 70*1024)
	event, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Args: []*tetragon.KprobeArgument{{
					Arg: &tetragon.KprobeArgument_BytesArg{BytesArg: want},
				}},
			},
		},
	})
	require.NoError(t, err)

	client := newIOReaderClient(bytes.NewReader(append(event, '\n')), false)
	getEventsClient, err := client.GetEvents(context.Background(), &tetragon.GetEventsRequest{})
	require.NoError(t, err)

	res, err := getEventsClient.Recv()
	require.NoError(t, err)
	require.Equal(t, want, res.GetProcessKprobe().GetArgs()[0].GetBytesArg())
}
