// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

type bindingPolicy struct {
	basePolicy
	template *tracingPolicyTemplate
}

func (m *state) getTemplateForPolicy(refPolID PolicyID) (*tracingPolicyTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := m.findTracingPolicyTemplate(refPolID)
	if index == -1 {
		return nil, fmt.Errorf("template with id %d does not exist", refPolID)
	}
	return m.tracingPolicyTemplates[index], nil
}

func (m *state) AddTracingPolicyBinding(polID PolicyID, refPolID PolicyID, namespace string, podLabelSelector *slimv1.LabelSelector,
	containerLabelSelector *slimv1.LabelSelector) error {
	m.log.Info("state: add tracing policy binding", "policy_id", polID)
	template, err := m.getTemplateForPolicy(refPolID)
	if err != nil {
		return err
	}
	policy := &bindingPolicy{
		template: template,
	}
	policy.setID(polID)
	return m.addPolicyCommon(policy, namespace, podLabelSelector, containerLabelSelector)
}

func (m *state) DeleteTracingPolicyBinding(polID PolicyID) error {
	m.log.Info("state: delete tracing policy binding", "policy_id", polID)
	return m.delPolicyCommon(polID)
}

func (pol *bindingPolicy) addCgroupIDs(log *slog.Logger, ids []CgroupID) error {
	var err error
	cgroupToPolicy := pol.template.cgroupToPolicy
	if cgroupToPolicy == nil {
		return fmt.Errorf("workload map is nil for bindingPolicy with id %d", pol.getID())
	}

	// Cleanup of the maps if something goes wrong
	defer func() {
		if err == nil {
			return
		}

		for _, id := range ids {
			err = cgroupToPolicy.Delete(id)
			if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Warn("failed to rollback cgroup map after error", "cgroup_id", id, "policy_id", pol.getID(), "error", err)
			}
		}
	}()

	for _, id := range ids {
		err = cgroupToPolicy.Update(id, pol.getID(), ebpf.UpdateNoExist)
		if err == nil {
			log.Info("state: add cgroup to cgroup map", "cgroup_id", id, "policy_id", pol.getID())
			continue
		}

		if errors.Is(err, ebpf.ErrKeyExist) {
			log.Warn("key already exists for cgroup", "cgroup_id", id, ". Overriding with policy_id", pol.getID())
			err = cgroupToPolicy.Update(id, pol.getID(), 0)
		}

		if err != nil {
			return fmt.Errorf("failed to insert (cgroup_id=%d, policy_id=%d) into workload map: %w", id, pol.getID(), err)
		}
	}
	return nil
}

func (pol *bindingPolicy) AddInitialCgroupIDs(state *state, ids []CgroupID) error {
	return pol.addCgroupIDs(state.log, ids)
}

func (pol *bindingPolicy) AddCgroupIDs(log *slog.Logger, ids []CgroupID) error {
	return pol.addCgroupIDs(log, ids)
}

func (pol *bindingPolicy) DelCgroupIDs(log *slog.Logger, ids []CgroupID) error {
	cgroupToPolicy := pol.template.cgroupToPolicy
	if cgroupToPolicy == nil {
		return fmt.Errorf("workload map is nil for bindingPolicy with id %d", pol.getID())
	}

	for _, id := range ids {
		err := cgroupToPolicy.Delete(id)
		log.Info("state: remove cgroup from cgroup map", "cgroup_id", id, "policy_id", pol.getID())

		if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Warn("failed to remove entry from cgroup map", "cgroup_id", id, "policy_id", pol.getID(), "error", err)
		}
	}
	return nil
}

func (pol *bindingPolicy) Close(log *slog.Logger) {
	var cgroupID uint64
	var policyID uint32
	currPolicyID := pol.getID()
	workloadIterator := pol.template.cgroupToPolicy.Iterate()
	for workloadIterator.Next(&cgroupID, &policyID) {
		if PolicyID(policyID) == currPolicyID {
			log.Info("state: delete cgroupID from cgroup map during close iteration", "cgroup_id", cgroupID, "policy_id", currPolicyID)
			if err := pol.template.cgroupToPolicy.Delete(cgroupID); err != nil {
				log.Warn("failed to delete cgroupID from cgroup map during bindingPolicy Close", "cgroup_id", cgroupID, "policy_id", currPolicyID, "error", err)
			}
		}
	}

	if err := workloadIterator.Err(); err != nil {
		log.Warn("failed to iterate over cgroup map during close iteration", "error", err)
	}
	log.Info("state: deleted cgroupIDs from cgroup map during close iteration", "policy_id", currPolicyID)
}
