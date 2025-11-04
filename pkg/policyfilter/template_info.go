// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type tracingPolicyTemplate struct {
	id             PolicyID
	cgroupToPolicy *ebpf.Map
}

func (m *state) findTracingPolicyTemplate(polID PolicyID) int32 {
	for i, info := range m.tracingPolicyTemplates {
		if info.id == polID {
			return int32(i)
		}
	}
	return -1
}

func (m *state) AddTracingPolicyTemplate(polID PolicyID, cgroupToPolicy *ebpf.Map) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log.Info("state: add tracing policy template", "template_id", polID)

	if m.findTracingPolicyTemplate(polID) != -1 {
		return fmt.Errorf("template with id %d already exists: not adding new one", polID)
	}

	info := &tracingPolicyTemplate{
		id:             polID,
		cgroupToPolicy: cgroupToPolicy,
	}

	m.tracingPolicyTemplates = append(m.tracingPolicyTemplates, info)
	return nil
}

func (m *state) DeleteTracingPolicyTemplate(polID PolicyID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.log.Info("state: delete tracing policy template", "template_id", polID)
	index := m.findTracingPolicyTemplate(polID)
	if index == -1 {
		return fmt.Errorf("template with id %d does not exist: not deleting", polID)
	}

	for i := range m.pods {
		pod := &m.pods[i]
		pod.delCachedPolicy(polID)
	}

	// delete all policies associated with this tracingPolicyTemplate
	for i := range m.policies {
		pol, ok := m.policies[i].(*bindingPolicy)
		if !ok {
			continue
		}
		if pol.template.id != polID {
			continue
		}

		// For each policy we need to remove the associated pods cached policy
		for i := range m.pods {
			pod := &m.pods[i]
			pod.delCachedPolicy(pol.getID())
		}

		m.log.Warn("state: delete policy because its parent template was deleted", "policy_id", pol.getID(), "template_id", polID)
		// we don't need to iterate over the ebpf maps to clean the cgroup in this case since we are deleting the whole policy
		m.policies = append(m.policies[:i], m.policies[i+1:]...)
	}

	m.tracingPolicyTemplates = append(m.tracingPolicyTemplates[:index], m.tracingPolicyTemplates[index+1:]...)
	return nil
}
