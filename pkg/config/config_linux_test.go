// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/option"
)

func TestKernelVersionSelection(t *testing.T) {
	// Test kernel version detection logic:
	// - v612: >= 6.12.0
	// - v61:  >= 6.1.0
	// - v513: >= 5.13.0
	// - RHEL7: < 3.11.0
	// - ForceSmallProgs disables all version variants

	// Save original config
	originalKernelVersion := option.Config.KernelVersion
	originalForceSmallProgs := option.Config.ForceSmallProgs
	defer func() {
		option.Config.KernelVersion = originalKernelVersion
		option.Config.ForceSmallProgs = originalForceSmallProgs
	}()

	testCases := []struct {
		name            string
		kernelVersion   string
		forceSmallProgs bool
		expectedV612    bool
		expectedV61     bool
		expectedV513    bool
		expectedRhel7   bool
	}{
		{
			name:            "kernel 6.12.0",
			kernelVersion:   "6.12.0",
			forceSmallProgs: false,
			expectedV612:    true,
			expectedV61:     true,
			expectedV513:    true,
			expectedRhel7:   false,
		},
		{
			name:            "kernel 6.1.0",
			kernelVersion:   "6.1.0",
			forceSmallProgs: false,
			expectedV612:    false,
			expectedV61:     true,
			expectedV513:    true,
			expectedRhel7:   false,
		},
		{
			name:            "kernel 5.13.0",
			kernelVersion:   "5.13.0",
			forceSmallProgs: false,
			expectedV612:    false,
			expectedV61:     false,
			expectedV513:    true,
			expectedRhel7:   false,
		},
		{
			name:            "kernel 3.10.0 (RHEL7)",
			kernelVersion:   "3.10.0",
			forceSmallProgs: false,
			expectedV612:    false,
			expectedV61:     false,
			expectedV513:    false,
			expectedRhel7:   true,
		},
		{
			name:            "kernel 6.12.0 with ForceSmallProgs",
			kernelVersion:   "6.12.0",
			forceSmallProgs: true,
			expectedV612:    false,
			expectedV61:     false,
			expectedV513:    false,
			expectedRhel7:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.KernelVersion = tc.kernelVersion
			option.Config.ForceSmallProgs = tc.forceSmallProgs

			assert.Equal(t, tc.expectedV612, EnableV612Progs(), "EnableV612Progs()")
			assert.Equal(t, tc.expectedV61, EnableV61Progs(), "EnableV61Progs()")
			assert.Equal(t, tc.expectedV513, EnableV513Progs(), "EnableV513Progs()")
			assert.Equal(t, tc.expectedRhel7, EnableRhel7Progs(), "EnableRhel7Progs()")
		})
	}
}

func TestBaseSensorObjSelection(t *testing.T) {
	originalKernelVersion := option.Config.KernelVersion
	originalForceSmallProgs := option.Config.ForceSmallProgs
	defer func() {
		option.Config.KernelVersion = originalKernelVersion
		option.Config.ForceSmallProgs = originalForceSmallProgs
	}()

	testCases := []struct {
		name            string
		kernelVersion   string
		forceSmallProgs bool
		expectedExit    string
		expectedFork    string
	}{
		// All kernels >= 5.13.0 use v513 variants for Exit/Fork objects
		{"kernel 6.12.0", "6.12.0", false, "bpf_exit_v513.o", "bpf_fork_v513.o"},
		{"kernel 6.1.0", "6.1.0", false, "bpf_exit_v513.o", "bpf_fork_v513.o"},
		{"kernel 5.13.0", "5.13.0", false, "bpf_exit_v513.o", "bpf_fork_v513.o"},
		// Kernels < 5.13.0 and not RHEL7 use base objects
		{"kernel 4.19.0", "4.19.0", false, "bpf_exit.o", "bpf_fork.o"},
		// RHEL7 kernels (< 3.11.0) use v310 variants
		{"kernel 3.10.0", "3.10.0", false, "bpf_exit_v310.o", "bpf_fork_v310.o"},
		// ForceSmallProgs overrides version detection, always uses base objects
		{"kernel 6.12.0 forced small", "6.12.0", true, "bpf_exit.o", "bpf_fork.o"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.KernelVersion = tc.kernelVersion
			option.Config.ForceSmallProgs = tc.forceSmallProgs

			assert.Equal(t, tc.expectedExit, ExitObj(), "ExitObj()")
			assert.Equal(t, tc.expectedFork, ForkObj(), "ForkObj()")
		})
	}
}

func TestAdditionalSensorObjSelection(t *testing.T) {
	// Test additional sensor object selection logic:
	// - Most sensors introduced v513 variants for kernels >= 5.13.0
	// - CgroupObj is an exception - it always uses the base object (no variants added)
	// - ForceSmallProgs overrides all version detection

	originalKernelVersion := option.Config.KernelVersion
	originalForceSmallProgs := option.Config.ForceSmallProgs
	defer func() {
		option.Config.KernelVersion = originalKernelVersion
		option.Config.ForceSmallProgs = originalForceSmallProgs
	}()

	testCases := []struct {
		name                    string
		kernelVersion           string
		forceSmallProgs         bool
		expectedBprmCommit      string
		expectedEnforcer        string
		expectedMultiEnforcer   string
		expectedFmodRetEnforcer string
		expectedLoader          string
		expectedCgroup          string
		expectedCgtracker       string
	}{
		{
			// Modern kernel: Most additional sensors use v513 variants for 5.13+
			// Exception: CgroupObj always uses base object
			name:                    "kernel 6.12.0",
			kernelVersion:           "6.12.0",
			forceSmallProgs:         false,
			expectedBprmCommit:      "bpf_execve_bprm_commit_creds_v513.o",
			expectedEnforcer:        "bpf_enforcer_v513.o",
			expectedMultiEnforcer:   "bpf_multi_enforcer_v513.o",
			expectedFmodRetEnforcer: "bpf_fmodret_enforcer_v513.o",
			expectedLoader:          "bpf_loader_v513.o",
			expectedCgroup:          "bpf_cgroup.o", // Always base object
			expectedCgtracker:       "bpf_cgtracker_v513.o",
		},
		{
			// v513 kernel: Same behavior as newer kernels - uses v513 variants
			name:                    "kernel 5.13.0",
			kernelVersion:           "5.13.0",
			forceSmallProgs:         false,
			expectedBprmCommit:      "bpf_execve_bprm_commit_creds_v513.o",
			expectedEnforcer:        "bpf_enforcer_v513.o",
			expectedMultiEnforcer:   "bpf_multi_enforcer_v513.o",
			expectedFmodRetEnforcer: "bpf_fmodret_enforcer_v513.o",
			expectedLoader:          "bpf_loader_v513.o",
			expectedCgroup:          "bpf_cgroup.o", // Always base object
			expectedCgtracker:       "bpf_cgtracker_v513.o",
		},
		{
			// Pre-v513 kernel: All additional sensors use base objects
			name:                    "kernel 4.19.0",
			kernelVersion:           "4.19.0",
			forceSmallProgs:         false,
			expectedBprmCommit:      "bpf_execve_bprm_commit_creds.o",
			expectedEnforcer:        "bpf_enforcer.o",
			expectedMultiEnforcer:   "bpf_multi_enforcer.o",
			expectedFmodRetEnforcer: "bpf_fmodret_enforcer.o",
			expectedLoader:          "bpf_loader.o",
			expectedCgroup:          "bpf_cgroup.o",
			expectedCgtracker:       "bpf_cgtracker.o",
		},
		{
			// ForceSmallProgs override: Always use base objects regardless of kernel version
			name:                    "kernel 6.12.0 forced small",
			kernelVersion:           "6.12.0",
			forceSmallProgs:         true,
			expectedBprmCommit:      "bpf_execve_bprm_commit_creds.o",
			expectedEnforcer:        "bpf_enforcer.o",
			expectedMultiEnforcer:   "bpf_multi_enforcer.o",
			expectedFmodRetEnforcer: "bpf_fmodret_enforcer.o",
			expectedLoader:          "bpf_loader.o",
			expectedCgroup:          "bpf_cgroup.o",
			expectedCgtracker:       "bpf_cgtracker.o",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.KernelVersion = tc.kernelVersion
			option.Config.ForceSmallProgs = tc.forceSmallProgs

			assert.Equal(t, tc.expectedBprmCommit, BprmCommitObj(), "BprmCommitObj()")
			assert.Equal(t, tc.expectedEnforcer, EnforcerObj(), "EnforcerObj()")
			assert.Equal(t, tc.expectedMultiEnforcer, MultiEnforcerObj(), "MultiEnforcerObj()")
			assert.Equal(t, tc.expectedFmodRetEnforcer, FmodRetEnforcerObj(), "FmodRetEnforcerObj()")
			assert.Equal(t, tc.expectedLoader, LoaderObj(), "LoaderObj()")
			assert.Equal(t, tc.expectedCgroup, CgroupObj(), "CgroupObj()")
			assert.Equal(t, tc.expectedCgtracker, CgtrackerObj(), "CgtrackerObj()")
		})
	}
}

func TestExecUpdateObjSelection(t *testing.T) {
	// Test ExecUpdateObj selection logic:
	// - Uses direct kernel version check for v612 (6.12+)
	// - Falls back to v513 for 5.13+ kernels
	// - Then uses kernel version check for v511 (5.11+)
	// - Finally falls back to EnableLargeProgs() check which is environment-dependent
	//
	// Note: ExecUpdateObj() calls EnableLargeProgs() as a fallback, which depends on
	// runtime BPF feature detection (bpf.HasProgramLargeSize() && bpf.HasSignalHelper()).
	// These functions can return different results in different environments:
	// - Local dev environment might return false
	// - CI environment (Ubuntu 24.04) might return true
	// This caused flaky test failures where kernel 4.19.0 would get "bpf_execve_map_update_v53.o"
	// in CI instead of the expected "bpf_execve_map_update.o". We use ForceSmallProgs=true
	// for the 4.19.0 test case to ensure deterministic behavior across all environments.

	originalKernelVersion := option.Config.KernelVersion
	originalForceSmallProgs := option.Config.ForceSmallProgs
	originalForceLargeProgs := option.Config.ForceLargeProgs
	defer func() {
		option.Config.KernelVersion = originalKernelVersion
		option.Config.ForceSmallProgs = originalForceSmallProgs
		option.Config.ForceLargeProgs = originalForceLargeProgs
	}()

	testCases := []struct {
		name               string
		kernelVersion      string
		forceSmallProgs    bool
		forceLargeProgs    bool
		expectedExecUpdate string
	}{
		{"kernel 6.12.0", "6.12.0", false, false, "bpf_execve_map_update_v612.o"},
		{"kernel 6.1.0", "6.1.0", false, false, "bpf_execve_map_update_v513.o"},
		{"kernel 5.13.0", "5.13.0", false, false, "bpf_execve_map_update_v513.o"},
		{"kernel 5.11.0", "5.11.0", false, false, "bpf_execve_map_update_v511.o"},
		// For kernel 4.19.0, use ForceSmallProgs=true to disable EnableLargeProgs() and ensure
		// deterministic behavior across environments (see function comment above)
		{"kernel 4.19.0", "4.19.0", true, false, "bpf_execve_map_update.o"},
		{"kernel 6.12.0 forced small", "6.12.0", true, false, "bpf_execve_map_update.o"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.KernelVersion = tc.kernelVersion
			option.Config.ForceSmallProgs = tc.forceSmallProgs
			option.Config.ForceLargeProgs = tc.forceLargeProgs

			assert.Equal(t, tc.expectedExecUpdate, ExecUpdateObj(), "ExecUpdateObj()")
		})
	}
}
