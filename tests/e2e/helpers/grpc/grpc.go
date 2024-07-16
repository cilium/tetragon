// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package grpc provides some helpers for contacting with the gRPC tetragon service.
// It depends on the grpc port being forwarded and available in the context
package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/tests/e2e/state"
)

// WaitForTracingPolicy checks that a tracing policy exists in all tetragon pods.
func WaitForTracingPolicy(ctx context.Context, policyName string) error {
	tetraPorts, ok := ctx.Value(state.GrpcForwardedPorts).(map[string]int)
	if !ok {
		return fmt.Errorf("failed to find tetragon grpc forwarded ports")
	}

	maxTries := 20
	for podName, grpcPort := range tetraPorts {
		addr := fmt.Sprintf("127.0.0.1:%d", grpcPort)
		// NB(kkourt): maybe it would make sense to cache the grpc connections in the
		// context, but we keep things simple for now.
		c, err := common.NewClient(ctx, addr, 2*time.Second)
		if err != nil {
			return fmt.Errorf("failed to create gRPC client to pod (%s) at forwared port (%d): %w", podName, grpcPort, err)
		}
		defer c.Close()

		for i := 0; i < maxTries; i++ {
			err = ensureTracingPolicy(c.Ctx, policyName, c.Client)
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			return fmt.Errorf("waiting for tracingpolicy '%s' on pod '%s' failed after %d attempts. Last error: %w",
				policyName, podName, maxTries, err)
		}
	}

	return nil
}

func ensureTracingPolicy(ctx context.Context, policyName string, client tetragon.FineGuidanceSensorsClient) error {
	res, err := client.ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return err
	}

	for _, pol := range res.GetPolicies() {
		if pol.GetName() == policyName {
			if pol.State == tetragon.TracingPolicyState_TP_STATE_ENABLED && pol.Error == "" {
				return nil
			}
			return fmt.Errorf("policy %s exists but is in state:%s (error:%s)",
				policyName,
				tetragon.TracingPolicyState_name[int32(pol.State)],
				pol.Error,
			)
		}
	}

	return fmt.Errorf("policy %s not found", policyName)
}
