// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package docker

import (
	"os/exec"
	"strings"
	"testing"
)

// Create creates a new docker container in the background. The container will
// be killed and removed on test cleanup.
// It returns the containerId on success, or an error if spawning the container failed.
func Create(tb testing.TB, args ...string) (containerId string) {
	// note: we are not using `--rm` so we can choose to wait on the container
	// with `docker wait`. We remove it manually below in t.Cleanup instead
	args = append([]string{"create"}, args...)
	id, err := exec.Command("docker", args...).Output()
	if err != nil {
		tb.Fatalf("failed to spawn docker container %v: %s", args, err)
	}

	containerId = strings.TrimSpace(string(id))
	tb.Cleanup(func() {
		err := exec.Command("docker", "rm", "--force", containerId).Run()
		if err != nil {
			tb.Logf("failed to remove container %s: %s", containerId, err)
		}
	})

	return containerId
}

// Start starts a new docker container with a given ID.
func Start(tb testing.TB, id string) {
	err := exec.Command("docker", "start", id).Run()
	if err != nil {
		tb.Fatalf("failed to start docker container %s: %s", id, err)
	}
}

// dockerRun starts a new docker container in the background. The container will
// be killed and removed on test cleanup.
// It returns the containerId on success, or an error if spawning the container failed.
func Run(tb testing.TB, args ...string) (containerId string) {
	// note: we are not using `--rm` so we can choose to wait on the container
	// with `docker wait`. We remove it manually below in t.Cleanup instead
	args = append([]string{"run", "--detach"}, args...)
	id, err := exec.Command("docker", args...).Output()
	if err != nil {
		tb.Fatalf("failed to spawn docker container %v: %s", args, err)
	}

	containerId = strings.TrimSpace(string(id))
	tb.Cleanup(func() {
		err := exec.Command("docker", "rm", "--force", containerId).Run()
		if err != nil {
			tb.Logf("failed to remove container %s: %s", containerId, err)
		}
	})

	return containerId
}

// dockerExec executes a command in a container.
func Exec(tb testing.TB, id string, args ...string) {
	args = append([]string{"exec", id}, args...)
	err := exec.Command("docker", args...).Run()
	if err != nil {
		tb.Fatalf("failed to exec in docker container %v: %s", args, err)
	}
}
