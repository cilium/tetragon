// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package grpc provides some helpers for contacting with the gRPC tetragon service.
// It depends on the grpc port being forwarded and available in the context
package grpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/tests/e2e/state"
)

// WaitForTracingPolicy checks that a tracing policy exists in all tetragon pods.
func WaitForTracingPolicy(ctx context.Context, policyName string) error {
	return WaitForTracingPolicyWithTime(ctx, policyName, 20, 1*time.Second)
}

func WaitForTracingPolicyWithTime(ctx context.Context, policyName string, maxTries int, timeout time.Duration) error {
	tetraConns, ok := ctx.Value(state.GrpcForwardedConns).(map[string]*grpc.ClientConn)
	if !ok {
		return errors.New("failed to find tetragon grpc forwarded ports")
	}

	for podName, grpcConn := range tetraConns {
		client := tetragon.NewFineGuidanceSensorsClient(grpcConn)
		var err error
		for range maxTries {
			err = ensureTracingPolicy(ctx, policyName, client)
			if err == nil {
				break
			}
			time.Sleep(timeout)
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
