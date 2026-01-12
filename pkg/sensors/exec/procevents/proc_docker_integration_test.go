// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build integration && linux

package procevents

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDockerContainerIdEnrichment verifies that LookupContainerId correctly
// extracts container IDs from real Docker cgroup paths.
// Regression test for https://github.com/cilium/tetragon/issues/4026
func TestDockerContainerIdEnrichment(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH, skipping integration test")
	}

	containerName := "tetragon-test-" + time.Now().Format("20060102150405")
	cmd := exec.Command("docker", "run", "-d", "--name", containerName, "alpine", "sleep", "30")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("failed to start docker container: %v (docker daemon may not be running)", err)
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", containerName).Run()
	})

	cmd = exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerName)
	out, err = cmd.Output()
	require.NoError(t, err, "failed to get container PID")
	pid := strings.TrimSpace(string(out))

	cgroupPath := "/proc/" + pid + "/cgroup"
	cgroupData, err := os.ReadFile(cgroupPath)
	require.NoError(t, err, "failed to read cgroup file: %s", cgroupPath)

	extractedID, offset := procsFindDockerId(string(cgroupData))

	require.NotEmpty(t, extractedID, "container ID should not be empty")
	require.True(t, strings.HasPrefix(containerID, extractedID),
		"extracted ID %s should be prefix of actual container ID %s", extractedID, containerID)

	t.Logf("Extracted container ID: %s (offset: %d)", extractedID, offset)
}
