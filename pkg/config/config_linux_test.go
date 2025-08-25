// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/option"
)

func TestKernelVersionSelection(t *testing.T) {
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
		{"kernel 6.12.0", "6.12.0", false, "bpf_exit_v612.o", "bpf_fork_v612.o"},
		{"kernel 6.1.0", "6.1.0", false, "bpf_exit_v61.o", "bpf_fork_v61.o"},
		{"kernel 5.13.0", "5.13.0", false, "bpf_exit_v513.o", "bpf_fork_v513.o"},
		{"kernel 4.19.0", "4.19.0", false, "bpf_exit.o", "bpf_fork.o"},
		{"kernel 3.10.0", "3.10.0", false, "bpf_exit_v310.o", "bpf_fork_v310.o"},
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
			name:                    "kernel 6.12.0",
			kernelVersion:           "6.12.0",
			forceSmallProgs:         false,
			expectedBprmCommit:      "bpf_execve_bprm_commit_creds_v612.o",
			expectedEnforcer:        "bpf_enforcer_v612.o",
			expectedMultiEnforcer:   "bpf_multi_enforcer_v612.o",
			expectedFmodRetEnforcer: "bpf_fmodret_enforcer_v612.o",
			expectedLoader:          "bpf_loader_v612.o",
			expectedCgroup:          "bpf_cgroup_v612.o",
			expectedCgtracker:       "bpf_cgtracker_v612.o",
		},
		{
			name:                    "kernel 5.13.0",
			kernelVersion:           "5.13.0",
			forceSmallProgs:         false,
			expectedBprmCommit:      "bpf_execve_bprm_commit_creds_v513.o",
			expectedEnforcer:        "bpf_enforcer_v513.o",
			expectedMultiEnforcer:   "bpf_multi_enforcer_v513.o",
			expectedFmodRetEnforcer: "bpf_fmodret_enforcer_v513.o",
			expectedLoader:          "bpf_loader_v513.o",
			expectedCgroup:          "bpf_cgroup_v513.o",
			expectedCgtracker:       "bpf_cgtracker_v513.o",
		},
		{
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
