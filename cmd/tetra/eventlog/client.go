// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventlog

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
)

type ClientWithContext struct {
	common.ConnWithContext
	Client tetragon.EventLogServiceClient
}

func NewClient() (*ClientWithContext, error) {
	ret, err := common.NewConnWithContext(context.Background(), common.ResolveServerAddress(), common.Timeout, "tetragon.EventLogService")
	if err != nil {
		return nil, err
	}

	c := &ClientWithContext{
		ConnWithContext: *ret,
		Client:          tetragon.NewEventLogServiceClient(ret.Conn),
	}

	return c, nil
}
