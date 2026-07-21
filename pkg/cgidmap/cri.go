// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"context"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/metrics/crimetrics"
)

// code for resolving missing cgroup ids by querying the CRI. Talking to the CRI
// provides authoritative answers and is used when --enable-cri is set.

// newCriResolver returns a resolver that finds container cgroup paths via the CRI.
func newCriResolver(m Map) *resolver {
	return newResolver(m, criContainerPath,
		crimetrics.CriResolutionsTotal, crimetrics.CriResolutionErrorsTotal)
}

// criContainerPath returns the absolute host cgroup path for a container by querying the CRI.
func criContainerPath(id unmappedID) (string, error) {
	ctx := context.Background()
	cli, err := cri.GetClient(ctx)
	if err != nil {
		return "", err
	}

	cgPath, err := cri.CgroupPath(ctx, cli, id.contID)
	if err != nil {
		return "", err
	}

	cgRoot, err := cgroups.HostCgroupRoot()
	if err != nil {
		return "", err
	}

	return filepath.Join(cgRoot, cgPath), nil
}
