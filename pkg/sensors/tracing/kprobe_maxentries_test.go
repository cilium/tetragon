// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

type testMap struct {
	name    string
	entries int
}

func runConfig(t *testing.T, config string, fn func(string, int)) {
	var err error

	err = os.WriteFile(testConfigFile, []byte(config), 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile,
		tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	for _, sensor := range sens {
		for _, load := range sensor.Progs {
			c := load.LC
			for _, p := range c.Programs {
				for _, id := range p.MapIDs {
					m, err := ebpf.NewMapFromID(id)
					if err != nil {
						t.Fatalf("can't open map id %d: %s\n", id, err)
					}
					info, err := m.Info()
					if err != nil {
						t.Fatalf("can't get map info: %s\n", err)
					}
					fn(info.Name, int(info.MaxEntries))
				}
			}
		}
	}

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func run(t *testing.T, maps []testMap, config string) {
	runConfig(t, config, func(name string, entries int) {
		for _, m := range maps {
			if name == m.name {
				t.Logf("checking '%s' expected entries: %d\n", m.name, m.entries)
				assert.Equal(t, m.entries, entries)
			}
		}
	})
}

func TestMaxEntries(t *testing.T) {
	t.Run("noresize", func(t *testing.T) {
		run(t, []testMap{
			{"fdinstall_map", 1},
			{"enforcer_data", 1},
			{"stack_trace_map", 1},
			{"ratelimit_map", 1},
			{"override_tasks", 1},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "1"
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
`)
	})

	t.Run("fdinstall_map", func(t *testing.T) {
		run(t, []testMap{
			{"fdinstall_map", fdInstallMapMaxEntries},
			{"enforcer_data", 1},
			{"stack_trace_map", 1},
			{"ratelimit_map", 1},
			{"override_tasks", 1},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "syswritefollowfdpsswd"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/test"
      matchActions:
      - action: FollowFD
        argFd: 0
        argName: 1
`)
	})

	t.Run("stack_trace_map", func(t *testing.T) {
		run(t, []testMap{
			{"fdinstall_map", 1},
			{"enforcer_data", 1},
			{"stack_trace_map", stackTraceMapMaxEntries},
			{"ratelimit_map", 1},
			{"override_tasks", 1},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "stack-traces-example"
spec:
  kprobes:
    - call: fd_install
      syscall: false
      selectors:
        - matchActions:
          - action: Post
            kernelStackTrace: true
            userStackTrace: true
`)
	})

	t.Run("ratelimit_map", func(t *testing.T) {
		run(t, []testMap{
			{"fdinstall_map", 1},
			{"enforcer_data", 1},
			{"stack_trace_map", 1},
			{"ratelimit_map", ratelimitMapMaxEntries},
			{"override_tasks", 1},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "process-creds-changed"
spec:
  kprobes:
  - call: "commit_creds"
    syscall: false
    args:
    - index: 0  # The new credentials to apply
      type: "cred"
    selectors:
      - matchNamespaces:
        - namespace: Pid
          operator: NotIn
          values:
          - "host_ns"
        matchActions:
        - action: Post
          rateLimit: "1m"
`)
	})

	t.Run("enforcer_data", func(t *testing.T) {
		if !bpf.HasSignalHelper() {
			t.Skip("skipping enforcer test, bpf_send_signal helper not available")
		}
		if !bpf.HasOverrideHelper() {
			t.Skip("skipping test, neither bpf_override_return nor fmod_ret for syscalls is available")
		}

		run(t, []testMap{
			{"fdinstall_map", 1},
			{"enforcer_data", enforcerMapMaxEntries},
			{"stack_trace_map", 1},
			{"ratelimit_map", 1},
			{"override_tasks", 1},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kill-syscalls"
spec:
  lists:
  - name: "dup"
    type: "syscalls"
    values:
    - "sys_dup"
  enforcers:
  - calls:
    - "list:dup"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:dup"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
      matchActions:
      - action: "NotifyEnforcer"
        argError: -1
        argSig: 9
`)
	})

	t.Run("override_tasks", func(t *testing.T) {
		if !bpf.HasOverrideHelper() {
			t.Skip("skipping test, neither bpf_override_return nor fmod_ret for syscalls is available")
		}

		run(t, []testMap{
			{"fdinstall_map", 1},
			{"enforcer_data", 1},
			{"stack_trace_map", 1},
			{"ratelimit_map", 1},
			{"override_tasks", overrideMapMaxEntries},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "override-example"
spec:
  kprobes:
  - call: "sys_symlinkat"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd"
      matchActions:
      - action: Override
        argError: -1
`)
	})
}
