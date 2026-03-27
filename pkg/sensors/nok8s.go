// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package sensors

import (
	"errors"

	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func (h *handler) updatePolicyFilter(tp tracingpolicy.TracingPolicy, tpID uint64) (policyfilter.PolicyID, error) {
	if _, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		return policyfilter.NoFilterID, errors.New("namespaced tracing policies not allowed in non-k8s build")
	}

	if ps := tp.TpSpec().PodSelector; ps != nil {
		return policyfilter.NoFilterID, errors.New("podSelector not allowed in non-k8s build")
	}

	if ps := tp.TpSpec().ContainerSelector; ps != nil {
		return policyfilter.NoFilterID, errors.New("containerSelector not allowed in non-k8s build")
	}

	return policyfilter.NoFilterID, nil
}
