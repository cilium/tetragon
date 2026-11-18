// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

type testMap struct {
	name    string
	entries int
}

func runConfig(t *testing.T, config string, fn func(string, int)) {
	var err error

	createCrdFile(t, config)

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile,
		tus.Conf().TetragonLib, observertesthelper.WithKeepCollection())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	for _, sensor := range sens {
		if sensor.Name == sensors.BaseSensorName {
			continue
		}
		for _, load := range sensor.Progs {
			if load.SharedStats {
				index := 0
				if load.RetProbe {
					index = 1
				}
				shared := sharedMultiKprobes[index]
				for _, cookie := range load.AttachData.(*program.MultiKprobeAttachData).Cookies {
					scope := uint32(cookie >> 32)
					// Inspect the maps selected by BPF, not local stand-ins.
					for name, registry := range shared.maps {
						if !multiPolicyMaps[name] {
							continue
						}
						var inner *ebpf.Map
						err := registry.MapHandle.Lookup(scope, &inner)
						if errors.Is(err, ebpf.ErrKeyNotExist) {
							fn(name, 0)
							continue
						}
						require.NoError(t, err)
						fn(name, int(inner.MaxEntries()))
						require.NoError(t, inner.Close())
					}
				}
				continue
			}
			require.NotNil(t, load.LC)
			for _, p := range load.LC.Programs {
				for _, id := range p.MapIDs {
					m, err := ebpf.NewMapFromID(id)
					require.NoError(t, err)
					info, err := m.Info()
					require.NoError(t, err)
					fn(info.Name, int(info.MaxEntries))
					require.NoError(t, m.Close())
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

func run(t *testing.T, maps []testMap, policy string) {
	seen := make(map[string]bool)
	runConfig(t, policy, func(name string, entries int) {
		for _, m := range maps {
			if name != m.name {
				continue
			}
			seen[name] = true
			// Shared programs need no dummy inner map for a disabled feature.
			if entries == 0 && m.entries == 1 && (name == "stack_trace_map" || name == "enforcer_data" || name == "override_tasks") {
				continue
			}
			assert.Equal(t, m.entries, entries, name)
		}
	})
	for _, m := range maps {
		// Small BPF programs do not reference the rate-limit map.
		if m.name == "ratelimit_map" && !config.EnableLargeProgs() {
			continue
		}
		require.True(t, seen[m.name], "map %s was not inspected", m.name)
	}
}

func TestMaxEntries(t *testing.T) {
	t.Run("noresize", func(t *testing.T) {
		run(t, []testMap{
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

	t.Run("substring_map", func(t *testing.T) {
		if !bpf.HasKfunc("bpf_strnstr") {
			t.Skip("skipping, no bpf_strnstr kfunc in kernel")
		}

		run(t, []testMap{
			{"substring_map", 2},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "substring-map"
spec:
  options:
  - name: "disable-kprobe-multi"
    value: "1"
  kprobes:
  - call: security_file_open
    syscall: false
    args:
    - index: 0
      type: file
    selectors:
    - matchArgs:
      - index: 0
        operator: "SubString"
        values:
        - test0
        - test1
`)
	})

	t.Run("substring_map_multi", func(t *testing.T) {
		if !bpf.HasKprobeMulti() || !bpf.HasKfunc("bpf_strnstr") {
			t.Skip("skipping, kprobe multi or bpf_strnstr kfunc unavailable")
		}

		run(t, []testMap{
			{"substring_map", 1}, // Each hook owns its substring map.
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "substring-map-multi"
spec:
  kprobes:
  - call: security_file_open
    syscall: false
    args:
    - index: 0
      type: file
    selectors:
    - matchArgs:
      - index: 0
        operator: "SubString"
        values:
        - test0
  - call: security_file_permission
    syscall: false
    args:
    - index: 0
      type: file
    selectors:
    - matchArgs:
      - index: 0
        operator: "SubString"
        values:
        - test1
`)
	})

	t.Run("substring_map_lsm", func(t *testing.T) {
		if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() || !bpf.HasKfunc("bpf_strnstr") {
			t.Skip("skipping, lsm programs or bpf_strnstr kfunc unavailable")
		}

		run(t, []testMap{
			{"substring_map", 2},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "substring-map-lsm"
spec:
  lsmhooks:
  - hook: "bprm_check_security"
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
    - matchArgs:
      - index: 0
        operator: "SubString"
        values:
        - test0
        - test1
`)
	})

	t.Run("stack_trace_map", func(t *testing.T) {
		run(t, []testMap{
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

	t.Run("enforcer_data", func(t *testing.T) {
		if !bpf.HasSignalHelper() {
			t.Skip("skipping enforcer test, bpf_send_signal helper not available")
		}
		if !bpf.HasOverrideHelper() {
			t.Skip("skipping test, neither bpf_override_return nor fmod_ret for syscalls is available")
		}

		run(t, []testMap{
			{"enforcer_data", enforcerMapMaxEntries},
			{"stack_trace_map", 1},
			{"ratelimit_map", 1},
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

	t.Run("override_tasks_lsm", func(t *testing.T) {
		if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
			t.Skip("skipping test, BPF LSM or large programs not available")
		}

		run(t, []testMap{
			{"override_tasks", overrideMapMaxEntries},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "override-lsm-example"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 0
      type: "file"
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

	t.Run("override_tasks_lsm_noresize", func(t *testing.T) {
		if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
			t.Skip("skipping test, BPF LSM or large programs not available")
		}

		run(t, []testMap{
			{"override_tasks", 1},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-no-override"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd"
`)
	})
}

func TestRateLimitMaxEntries(t *testing.T) {
	if !config.EnableLargeProgs() {
		t.Skip("rate limiting requires large BPF programs")
	}

	t.Run("kprobe", func(t *testing.T) {
		run(t, []testMap{
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

	t.Run("lsm", func(t *testing.T) {
		if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
			t.Skip("skipping, BPF LSM or large programs unavailable")
		}

		run(t, []testMap{
			{"ratelimit_map", ratelimitMapMaxEntries},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-ratelimit-map"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: "1m"
`)
	})

	t.Run("tracepoint", func(t *testing.T) {
		run(t, []testMap{
			{"ratelimit_map", ratelimitMapMaxEntries},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-ratelimit-map"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
    args:
    - index: 5
      type: "int32"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: "1m"
`)
	})

	t.Run("rawtp", func(t *testing.T) {
		run(t, []testMap{
			{"ratelimit_map", ratelimitMapMaxEntries},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "rawtp-ratelimit-map"
spec:
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    raw: true
    args:
    - index: 1
      type: "int64"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: "1m"
`)
	})

	t.Run("uprobe", func(t *testing.T) {
		uprobeBinary := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1")
		run(t, []testMap{
			{"ratelimit_map", ratelimitMapMaxEntries},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-ratelimit-map"
spec:
  uprobes:
  - path: "`+uprobeBinary+`"
    symbols:
    - "main"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: "1m"
`)
	})

	t.Run("usdt", func(t *testing.T) {
		if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
			t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
		}

		usdt := testutils.RepoRootPath("contrib/tester-progs/usdt")
		run(t, []testMap{
			{"ratelimit_map", ratelimitMapMaxEntries},
		}, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdt-ratelimit-map"
spec:
  usdts:
  - path: "`+usdt+`"
    provider: "test"
    name: "usdt0"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: "1m"
`)
	})
}

func TestUprobeStackTraceMapMaxEntries(t *testing.T) {
	uprobeBinary := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1")
	found := false

	runConfig(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-stack-traces"
spec:
  uprobes:
  - path: "`+uprobeBinary+`"
    symbols:
    - "main"
    selectors:
    - matchActions:
      - action: Post
        userStackTrace: true
`, func(name string, entries int) {
		if name == "stack_trace_map" {
			found = true
			assert.Equal(t, stackTraceMapMaxEntries, entries)
		}
	})

	assert.True(t, found, "stack_trace_map was not loaded")
}
