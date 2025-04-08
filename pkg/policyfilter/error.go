// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
)

// podNamespaceConflictError: even if a pod changes, we expect the namespace to remain the same
type podNamespaceConflictError struct {
	podID        PodID
	oldNs, newNs string
}

func (e *podNamespaceConflictError) Error() string {
	return fmt.Sprintf("conflicting namespaces for pod with id '%s': old='%s' vs new='%s'",
		e.podID.String(), e.oldNs, e.newNs)
}

// ErrorLabel returns an error label with a small cardinality so it can be used in metrics
func ErrorLabel(err error) string {
	if err == nil {
		return policyfiltermetrics.NoErr.String()
	}

	var podNamespaceConflictErr *podNamespaceConflictError
	if errors.As(err, &podNamespaceConflictErr) {
		return policyfiltermetrics.PodNamespaceConflictErr.String()
	}
	return policyfiltermetrics.GenericErr.String()
}
