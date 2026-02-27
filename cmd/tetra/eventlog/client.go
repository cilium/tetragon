// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventlog

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type ClientWithContext struct {
	conn          *grpc.ClientConn
	Client        tetragon.EventLogServiceClient
	ctx           context.Context
	timeoutCancel context.CancelFunc
}

func (c ClientWithContext) Close() {
	c.conn.Close()
	c.timeoutCancel()
}

func NewClient() (*ClientWithContext, error) {
	c := &ClientWithContext{}
	c.ctx, c.timeoutCancel = context.WithTimeout(context.Background(), common.Timeout)

	var err error
	c.conn, err = grpc.NewClient(
		common.ResolveServerAddress(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithMaxCallAttempts(common.Retries+1), // maxAttempt includes the first call
	)
	if err != nil {
		return nil, err
	}
	c.Client = tetragon.NewEventLogServiceClient(c.conn)

	return c, nil
}
