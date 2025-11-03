//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// PolicyInfo contains information about a policy that hooks a specific function
type PolicyInfo struct {
	Policy   tracingpolicy.TracingPolicy
	PolicyID policyfilter.PolicyID
	Name     string
	// KprobeSpecs contains the kprobe specifications for this policy
	KprobeSpecs []KprobeSpec
}

// KprobeSpec represents a kprobe specification from a policy
type KprobeSpec struct {
	FunctionName string
	Syscall      bool
	RetProbe     bool
	Instance     int
	// Additional fields from the original kprobe spec can be added here
}

// ConsolidatedProgram represents a BPF program that handles multiple policies
type ConsolidatedProgram struct {
	Program   *program.Program
	Policies  []PolicyInfo
	ConfigMap *program.Map
	// FunctionName is the kernel function this program is attached to
	FunctionName string
	// EntryIDs tracks the idtable entries for this consolidated program
	EntryIDs []idtable.EntryID
}

// FunctionAttachmentManager manages consolidation of BPF programs across policies
type FunctionAttachmentManager struct {
	// functionPolicies maps function name to list of policies hooking it
	functionPolicies map[string][]PolicyInfo
	// consolidatedPrograms maps function name to consolidated BPF program
	consolidatedPrograms map[string]*ConsolidatedProgram
	// mutex protects the maps above
	mutex sync.RWMutex
}

// NewFunctionAttachmentManager creates a new FunctionAttachmentManager
func NewFunctionAttachmentManager() *FunctionAttachmentManager {
	return &FunctionAttachmentManager{
		functionPolicies:     make(map[string][]PolicyInfo),
		consolidatedPrograms: make(map[string]*ConsolidatedProgram),
	}
}

// AddPolicy adds a policy to the manager and identifies functions that can be consolidated
func (fam *FunctionAttachmentManager) AddPolicy(policy tracingpolicy.TracingPolicy, policyID policyfilter.PolicyID) error {
	fam.mutex.Lock()
	defer fam.mutex.Unlock()

	spec := policy.TpSpec()
	if spec == nil || len(spec.KProbes) == 0 {
		// No kprobes in this policy, nothing to consolidate
		return nil
	}

	policyInfo := PolicyInfo{
		Policy:   policy,
		PolicyID: policyID,
		Name:     policy.TpName(),
	}

	// Extract kprobe specifications from the policy
	for _, kprobe := range spec.KProbes {
		kprobeSpec := KprobeSpec{
			FunctionName: kprobe.Call,
			Syscall:      kprobe.Syscall,
			RetProbe:     kprobe.Return,
			Instance:     0, // Will be set later if needed
		}
		policyInfo.KprobeSpecs = append(policyInfo.KprobeSpecs, kprobeSpec)

		// Add this policy to the function's policy list
		fam.functionPolicies[kprobe.Call] = append(fam.functionPolicies[kprobe.Call], policyInfo)
	}

	return nil
}

// RemovePolicy removes a policy from the manager
func (fam *FunctionAttachmentManager) RemovePolicy(policyName string) error {
	fam.mutex.Lock()
	defer fam.mutex.Unlock()

	// Remove policy from all function policy lists
	for funcName, policies := range fam.functionPolicies {
		var filteredPolicies []PolicyInfo
		for _, policy := range policies {
			if policy.Name != policyName {
				filteredPolicies = append(filteredPolicies, policy)
			}
		}
		
		if len(filteredPolicies) == 0 {
			delete(fam.functionPolicies, funcName)
			// Also remove any consolidated program for this function
			delete(fam.consolidatedPrograms, funcName)
		} else {
			fam.functionPolicies[funcName] = filteredPolicies
		}
	}

	return nil
}

// GetConsolidationCandidates returns functions that have multiple policies and can be consolidated
func (fam *FunctionAttachmentManager) GetConsolidationCandidates() map[string][]PolicyInfo {
	fam.mutex.RLock()
	defer fam.mutex.RUnlock()

	candidates := make(map[string][]PolicyInfo)
	for funcName, policies := range fam.functionPolicies {
		if len(policies) > 1 {
			// Check if all policies are compatible for consolidation
			if fam.areCompatibleForConsolidation(policies) {
				candidates[funcName] = policies
			}
		}
	}

	return candidates
}

// areCompatibleForConsolidation checks if policies can be consolidated into a single BPF program
func (fam *FunctionAttachmentManager) areCompatibleForConsolidation(policies []PolicyInfo) bool {
	if len(policies) <= 1 {
		return false
	}

	// For now, we'll use simple compatibility rules:
	// 1. All policies must hook the same function (already guaranteed by caller)
	// 2. All policies must have the same syscall flag
	// 3. All policies must have the same retprobe flag
	// 4. No policy should have instance > 0 (multi-instance not supported with consolidation)

	firstPolicy := policies[0]
	if len(firstPolicy.KprobeSpecs) == 0 {
		return false
	}
	firstSpec := firstPolicy.KprobeSpecs[0]

	for _, policy := range policies[1:] {
		if len(policy.KprobeSpecs) == 0 {
			return false
		}
		spec := policy.KprobeSpecs[0]
		
		if spec.Syscall != firstSpec.Syscall ||
			spec.RetProbe != firstSpec.RetProbe ||
			spec.Instance > 0 {
			return false
		}
	}

	return true
}

// CreateConsolidatedProgram creates a consolidated BPF program for a function with multiple policies
func (fam *FunctionAttachmentManager) CreateConsolidatedProgram(funcName string, policies []PolicyInfo) (*ConsolidatedProgram, error) {
	fam.mutex.Lock()
	defer fam.mutex.Unlock()

	if existing, exists := fam.consolidatedPrograms[funcName]; exists {
		return existing, nil
	}

	consolidated := &ConsolidatedProgram{
		FunctionName: funcName,
		Policies:     policies,
	}

	fam.consolidatedPrograms[funcName] = consolidated
	return consolidated, nil
}

// GetConsolidatedProgram returns the consolidated program for a function, if it exists
func (fam *FunctionAttachmentManager) GetConsolidatedProgram(funcName string) (*ConsolidatedProgram, bool) {
	fam.mutex.RLock()
	defer fam.mutex.RUnlock()

	prog, exists := fam.consolidatedPrograms[funcName]
	return prog, exists
}

// ShouldConsolidate returns true if the given function should use a consolidated program
func (fam *FunctionAttachmentManager) ShouldConsolidate(funcName string) bool {
	fam.mutex.RLock()
	defer fam.mutex.RUnlock()

	policies, exists := fam.functionPolicies[funcName]
	if !exists {
		return false
	}

	return len(policies) > 1 && fam.areCompatibleForConsolidation(policies)
}

// GetStats returns statistics about consolidation
func (fam *FunctionAttachmentManager) GetStats() ConsolidationStats {
	fam.mutex.RLock()
	defer fam.mutex.RUnlock()

	stats := ConsolidationStats{
		TotalFunctions:        len(fam.functionPolicies),
		ConsolidatedFunctions: len(fam.consolidatedPrograms),
	}

	for _, policies := range fam.functionPolicies {
		stats.TotalPolicies += len(policies)
		if len(policies) > 1 {
			stats.ConsolidationCandidates++
		}
	}

	return stats
}

// ConsolidationStats provides statistics about the consolidation process
type ConsolidationStats struct {
	TotalFunctions           int
	TotalPolicies           int
	ConsolidatedFunctions   int
	ConsolidationCandidates int
}

func (cs ConsolidationStats) String() string {
	return fmt.Sprintf("Functions: %d, Policies: %d, Consolidated: %d, Candidates: %d",
		cs.TotalFunctions, cs.TotalPolicies, cs.ConsolidatedFunctions, cs.ConsolidationCandidates)
}
