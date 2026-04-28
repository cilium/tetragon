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
	namespace := tp.TpNamespace()
	podSelector := tp.TpSpec().PodSelector
	containerSelector := tp.TpSpec().ContainerSelector
	hostSelector := tp.TpSpec().HostSelector

	// This is checked with a kubebuilder XValidation. But we also check that here just to be on the safe side.
	if namespace != "" && hostSelector != nil {
		return policyfilter.NoFilterID, errors.New("TracingPolicyNamespaced cannot match host workloads so spec.hostSelector should be null")
	}

	if hostSelector != nil && (len(hostSelector.MatchLabels)+len(hostSelector.MatchExpressions) > 0) {
		return policyfilter.NoFilterID, errors.New("spec.hostSelector does not support arbitrary labels. Only null (default) and {} (all) is supported for now")
	}

	// If the user specifies a podSelector but don't specify a containerSelector,
	// we assume that the user cares for all containers inside the pods that match.
	if podSelector != nil && containerSelector == nil {
		containerSelector = &slimv1.LabelSelector{}
	}

	// If the user specifies a containerSelector but don't specify a podSelector,
	// we assume that the user cares for containers that match inside all pods.
	if containerSelector != nil && podSelector == nil {
		podSelector = &slimv1.LabelSelector{}
	}

	// This is the case where all of podSelector, containerSelector, hostSelector are excplicitly defined to be {}.
	// In that case we match everything so no need to apply a policyfilter.
	matchAll := func(s *slimv1.LabelSelector) bool {
		return (s != nil && (len(s.MatchLabels)+len(s.MatchExpressions) == 0))
	}
	globalSelectorsMatchAll := matchAll(podSelector) && matchAll(containerSelector) && matchAll(hostSelector)

	// This covers the "special" case where all of podSelector, containerSelector, hostSelector are nil (default).
	// In that case we match everything so no need to apply a policyfilter.
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

	// A namespaced policy with podSelector: null (default) and containerSelector: null (default) means that it will
	// match all pods and containers within a specific namespace
	if namespace != "" && (podSelector == nil && containerSelector == nil) {
		podSelector = &slimv1.LabelSelector{}
		containerSelector = &slimv1.LabelSelector{}
	}

	filterID := policyfilter.PolicyID(tpID)
	if err := h.pfState.AddPolicy(filterID, namespace, podSelector, containerSelector, hostSelector); err != nil {
		return policyfilter.NoFilterID, err
	}
	return filterID, nil
}
