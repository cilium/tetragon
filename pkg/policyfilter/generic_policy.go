// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

type genericPolicy struct {
	basePolicy
	// polMap is the (inner) policy map for this policy
	polMap polMap
}

// AddGenericPolicy adds a generic policy
func (m *state) AddGenericPolicy(polID PolicyID, namespace string, podLabelSelector *slimv1.LabelSelector,
	containerLabelSelector *slimv1.LabelSelector) error {
	policy := &genericPolicy{}
	policy.setID(polID)
	return m.addPolicyCommon(policy, namespace, podLabelSelector, containerLabelSelector)
}

func (m *state) DeleteGenericPolicy(polID PolicyID) error {
	if polID == NoFilterPolicyID {
		// we do nothing
		return nil
	}

	m.mu.Lock()
	// delete entry in policy outerMap
	if err := m.pfMap.policyMap.Delete(polID); err != nil && err != ebpf.ErrKeyNotExist {
		m.log.Warn("failed to remove policy from external map", "policy-id", polID)
	}
	// delete entry in cgroup map
	if err := m.pfMap.deletePolicyIDInCgroupMap(polID); err != nil && err != ebpf.ErrKeyNotExist {
		m.log.Warn("failed to remove policy from cgroup map", "policy-id", polID)
	}
	m.mu.Unlock()

	return m.delPolicyCommon(polID)
}

func (pol *genericPolicy) AddInitialCgroupIDs(state *state, ids []CgroupID) error {
	var err error
	pol.polMap, err = state.pfMap.newPolicyMap(pol.getID(), ids)
	return err
}

func (pol *genericPolicy) AddCgroupIDs(_ *slog.Logger, ids []CgroupID) error {
	if err := pol.polMap.addCgroupIDs(ids); err != nil {
		return fmt.Errorf("failed to update policy map. error: %w", err)
	}
	if err := pol.polMap.addPolicyIDs(pol.id, ids); err != nil {
		return fmt.Errorf("failed to update cgroup map. error: %w", err)
	}
	return nil

}

func (pol *genericPolicy) DelCgroupIDs(_ *slog.Logger, ids []CgroupID) error {
	return pol.polMap.delCgroupIDs(pol.id, ids)
}

func (pol *genericPolicy) Close(_ *slog.Logger) {
	pol.polMap.Inner.Close()
}
