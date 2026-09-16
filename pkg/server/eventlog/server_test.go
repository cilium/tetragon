// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventlog

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type testLogParamsSetter struct{}

func (testLogParamsSetter) SetLogParams(Params) error {
	return nil
}

func TestGetEventLogParamsReturnsSnapshot(t *testing.T) {
	server := New(testLogParamsSetter{})
	ctx := context.Background()

	maxSize := int32(1)
	_, err := server.SetEventLogParams(ctx, &tetragon.SetEventLogParamsRequest{MaxSize: &maxSize})
	require.NoError(t, err)

	params, err := server.GetEventLogParams(ctx, &tetragon.GetEventLogParamsRequest{})
	require.NoError(t, err)

	maxSize = 2
	_, err = server.SetEventLogParams(ctx, &tetragon.SetEventLogParamsRequest{MaxSize: &maxSize})
	require.NoError(t, err)
	require.Equal(t, int32(1), params.MaxSize)

	params, err = server.GetEventLogParams(ctx, &tetragon.GetEventLogParamsRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(2), params.MaxSize)
}

func TestConcurrentGetAndSetEventLogParams(t *testing.T) {
	server := New(testLogParamsSetter{})
	ctx := context.Background()
	errs := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 1000 {
			maxSize := int32(i)
			_, err := server.SetEventLogParams(ctx, &tetragon.SetEventLogParamsRequest{MaxSize: &maxSize})
			if err != nil {
				errs <- err
				return
			}
		}
	})
	wg.Go(func() {
		for range 1000 {
			params, err := server.GetEventLogParams(ctx, &tetragon.GetEventLogParamsRequest{})
			if err != nil {
				errs <- err
				return
			}
			_ = params.MaxSize
		}
	})
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}
