// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package sensors

import (
	"errors"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// updatePolicyFilter will update the policyfilter state so that filtering for
// i) namespaced policies and ii) pod label filters happens.
//
// It returns:
//
//	policyfilter.NoFilterID, nil if no filtering is needed
//	policyfilter.PolicyID(tpID), nil if filtering is needed and policyfilter has been successfully set up
//	_, err if an error occurred
func (h *handler) updatePolicyFilter(tp tracingpolicy.TracingPolicy, tpID uint64) (policyfilter.PolicyID, error) {
	var namespace string
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	// matches nothing           | tp.TpSpec().PodSelector == nil
	// matches everything        | tp.TpSpec().PodSelector != nil && (len(ps.MatchLabels) + len(ps.MatchExpressions) == 0)
	// matches based on selector | tp.TpSpec().PodSelector != nil && (len(ps.MatchLabels) + len(ps.MatchExpressions) != 0)
	podSelector := tp.TpSpec().PodSelector

	// matches nothing           | tp.TpSpec().ContainerSelector == nil
	// matches everything        | tp.TpSpec().ContainerSelector != nil && (len(ps.MatchLabels) + len(ps.MatchExpressions) == 0)
	// matches based on selector | tp.TpSpec().ContainerSelector != nil && (len(ps.MatchLabels) + len(ps.MatchExpressions) != 0)
	containerSelector := tp.TpSpec().ContainerSelector

	// matches nothing           | tp.TpSpec().HostSelector == nil
	// matches everything        | tp.TpSpec().HostSelector != nil && (len(ps.MatchLabels) + len(ps.MatchExpressions) == 0)
	// matches based on selector | Not supported yet
	hostSelector := tp.TpSpec().HostSelector
	if hostSelector != nil && (len(hostSelector.MatchLabels)+len(hostSelector.MatchExpressions) > 0) {
		return policyfilter.NoFilterID, errors.New("spec.hostSelector does not support arbitrary labels. Only ~ (empty) and {} (all) is supported for now")
	}

	// This is the case where all of PodSelector, ContainerSelector, HostSelector are {}.
	// In that case we match everything so no need to apply a policyfilter as well.
	matchAll := func(s *slimv1.LabelSelector) bool {
		return (s != nil && (len(s.MatchLabels)+len(s.MatchExpressions) == 0))
	}
	globalSelectorsMatchAll := matchAll(podSelector) && matchAll(containerSelector) && matchAll(hostSelector)

	// This covers the case where all of PodSelector, ContainerSelector, HostSelector are nil.
	// This is not intended to be used by the end users but it reduces the boilerplate code
	// in our non-k8s testing by a large factor.
	matchNothing := func(s *slimv1.LabelSelector) bool {
		return s == nil
	}
	globalSelectorsMatchNothing := matchNothing(podSelector) && matchNothing(containerSelector) && matchNothing(hostSelector)

	// we do not call AddPolicy unless filtering is actually needed. This
	// means that if policyfilter is disabled
	// (option.Config.EnablePolicyFilter is false) then loading the policy
	// will only fail if filtering is required.
	if namespace == "" && (globalSelectorsMatchAll || globalSelectorsMatchNothing) {
		return policyfilter.NoFilterID, nil
	}
	filterID := policyfilter.PolicyID(tpID)
	if err := h.pfState.AddPolicy(filterID, namespace, podSelector, containerSelector, hostSelector); err != nil {
		return policyfilter.NoFilterID, err
	}
	return filterID, nil
}
