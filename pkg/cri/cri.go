// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// code for connecting to the cri

package cri

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/cilium/tetragon/pkg/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var (
	defaultEndpoints = []string{
		"unix:///run/containerd/containerd.sock",
		"unix:///run/crio/crio.sock",
		"unix:///var/run/cri-dockerd.sock",
	}

	errNotUnix     = errors.New("only unix endpoints are supported")
	errCRIDisabled = errors.New("connecting to CRI is disabled")
)

func NewClient(ctx context.Context, endpoint string) (criapi.RuntimeServiceClient, error) {
	if len(endpoint) > 0 {
		return newClientTry(ctx, endpoint)
	}

	for _, ep := range defaultEndpoints {
		if cli, err := newClientTry(ctx, ep); err == nil {
			return cli, nil
		}
	}
	return nil, fmt.Errorf("unable to connect to CRI endpoints (%q)", defaultEndpoints)
}

func newClientTry(ctx context.Context, endpoint string) (criapi.RuntimeServiceClient, error) {

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "unix" {
		return nil, errNotUnix
	}

	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	rtcli := criapi.NewRuntimeServiceClient(conn)
	if _, err := rtcli.Version(ctx, &criapi.VersionRequest{}); err != nil {
		return nil, fmt.Errorf("validate CRI v1 runtime API for endpoint %q: %w", endpoint, err)
	}

	return rtcli, nil
}

var (
	glClient criapi.RuntimeServiceClient
	glMu     sync.Mutex
)

// GetState returns global client for CRI
func GetClient(ctx context.Context) (criapi.RuntimeServiceClient, error) {
	if !option.Config.EnableCRI {
		return nil, errCRIDisabled
	}
	glMu.Lock()
	defer glMu.Unlock()
	if glClient != nil {
		return glClient, nil
	}

	var err error
	glClient, err = NewClient(ctx, option.Config.CRIEndpoint)
	return glClient, err
}
