// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package dump

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// GetProcessCacheForDump retrieves the internal process cache from the Tetragon agent
// via gRPC, applying optional filters for zero-refcount entries and execve map processes.
func GetProcessCacheForDump(ctx context.Context, client tetragon.FineGuidanceSensorsClient, maxCallRecvMsgSize int, skipZeroRefcnt bool, excludeExecveMapProcesses bool) ([]*tetragon.ProcessInternal, error) {
	req := tetragon.GetDebugRequest{
		Flag: tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE,
		Arg: &tetragon.GetDebugRequest_Dump{
			Dump: &tetragon.DumpProcessCacheReqArgs{
				SkipZeroRefcnt:            skipZeroRefcnt,
				ExcludeExecveMapProcesses: excludeExecveMapProcesses,
			},
		},
	}
	res, err := client.GetDebug(ctx, &req, grpc.MaxCallRecvMsgSize(maxCallRecvMsgSize))
	if err != nil {
		return nil, fmt.Errorf("failed to get process dump debug info: %w", err)
	}

	if res.Flag != tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE {
		return nil, fmt.Errorf("unexpected response flag: %s", res.Flag)
	}

	return res.GetProcesses().Processes, nil
}
