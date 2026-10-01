// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// maxNameLength is the DNS-1123 subdomain limit, applied to metadata.name by
// apimachinery in k8s builds and by validateObjectName in non-k8s builds.
const maxNameLength = 253

func TestKprobeValidationReturnWithoutArg(t *testing.T) {
	// missing returnArg while having return: true
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "missing-returnarg"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
`
	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ReturnArg not specified with Return=true.")
}

func testUprobeValidationSymbolsAddrsOffsets(t *testing.T, withSymbol, withAdrr, withOff bool) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
`
	if withSymbol {
		crd += "    symbols: [\"test_3\"]\n"
	}
	if withAdrr {
		crd += "    addrs: [0x985256]\n"
	}
	if withOff {
		crd += "    offsets: [0x9156366]\n"
	}

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "symbols, addrs or offsets defined")
}

func TestUprobeValidationSymbolsAddrsOffsets(t *testing.T) {
	t.Run("SymbolAddrOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, true, true)
	})

	t.Run("SymbolAddr", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, true, false)
	})

	t.Run("SymbolOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, false, true)
	})

	t.Run("AddrOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, false, true, true)
	})
}

func TestUprobeValidationReturnWithoutArg(t *testing.T) {
	// missing returnArg while having return: true
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
    symbols:
    - "test_3"
    return: true
`

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ReturnArg not specified with Return=true.")
}

func testUprobeValidationOverrideArgNewSymbolAddrOffset(t *testing.T, withSymbol, withAdrr, withOff bool) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
    symbols:
    - "test_1"
    selectors:
    - matchActions:
      - action: Override
`
	if withSymbol {
		crd += "        argNewSymbol: \"test_3\"\n"
	}
	if withAdrr {
		crd += "        argNewAddr: 0x985256\n"
	}
	if withOff {
		crd += "        argNewOffset: 0x9156366\n"
	}

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "argNewSymbol, argNewAddr or argNewOffset defined")
}

func TestUprobeValidationOverrideArgNewSymbolAddrOffset(t *testing.T) {
	t.Run("NewSymbolAddrOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, true, true)
	})

	t.Run("NewSymbolAddr", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, true, false)
	})

	t.Run("NewSymbolOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, false, true)
	})

	t.Run("NewAddrOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, false, true, true)
	})
}

func TestMatchCmdArgsYAML(t *testing.T) {
	policy, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: match-command-arguments
spec:
  kprobes:
  - call: security_file_permission
    selectors:
    - matchCmdArgs:
      - index: 0
        operator: Equal
        values:
        - -flag1=value1
      - index: 1
        operator: Prefix
        values:
        - /my/path
`)
	require.NoError(t, err)

	selectors := policy.TpSpec().KProbes[0].Selectors
	require.Equal(t, []v1alpha1.CmdArgSelector{
		{
			Index:    0,
			Operator: "Equal",
			Values:   []string{"-flag1=value1"},
		},
		{
			Index:    1,
			Operator: "Prefix",
			Values:   []string{"/my/path"},
		},
	}, selectors[0].MatchCmdArgs)
}

func TestMatchCmdArgsOperatorValidation(t *testing.T) {
	_, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: match-command-arguments
spec:
  kprobes:
  - call: security_file_permission
    selectors:
    - matchCmdArgs:
      - index: 0
        operator: Invalid
        values:
        - value
`)
	require.Error(t, err)
}

// TestTracepointNameSchemaValidation checks the CRD pattern on
// spec.tracepoints[].subsystem and spec.tracepoints[].event, which keeps path
// separators and ".." out of the tracefs format path and the pin path.
func TestTracepointNameSchemaValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		subsystem string
		event     string
		wantErr   bool
	}{
		{name: "valid", subsystem: "syscalls", event: "sys_enter_openat"},
		// raw tracepoints such as 9p/9p_client_req start with a digit
		{name: "leading digit", subsystem: "9p", event: "9p_client_req"},
		{name: "dash", subsystem: "sub-sys", event: "some-event"},
		{name: "leading underscore", subsystem: "_underscore", event: "_underscore"},
		{name: "empty subsystem", subsystem: "", event: "sys_enter_openat", wantErr: true},
		{name: "empty event", subsystem: "syscalls", event: "", wantErr: true},
		{name: "slash in subsystem", subsystem: "syscalls/evil", event: "sys_enter_openat", wantErr: true},
		{name: "slash in event", subsystem: "syscalls", event: "evil/sys_enter_openat", wantErr: true},
		{name: "dotdot in subsystem", subsystem: "../../etc", event: "passwd", wantErr: true},
		{name: "dotdot in event", subsystem: "syscalls", event: "..", wantErr: true},
		{name: "leading dash in subsystem", subsystem: "-syscalls", event: "sys_enter_openat", wantErr: true},
		{name: "colon in event", subsystem: "syscalls", event: "sys:enter", wantErr: true},
		{name: "space in subsystem", subsystem: "sys calls", event: "sys_enter_openat", wantErr: true},
		{name: "nul in event", subsystem: "syscalls", event: "sys_enter\x00", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromYAML(fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: tracepoint-names
spec:
  tracepoints:
  - subsystem: %q
    event: %q
`, tc.subsystem, tc.event))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFromYAMLNameValidation(t *testing.T) {
	tpWithName := func(name string) string {
		return fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %s
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
`, name)
	}

	valid := []string{
		"my-policy",
		"policy.with.dots",
		"p",
		`"0123"`,
		strings.Repeat("a", maxNameLength),
	}
	for _, name := range valid {
		_, err := FromYAML(tpWithName(name))
		require.NoError(t, err, "name %q should be accepted", name)
	}

	invalid := []string{
		`".."`,
		`"."`,
		`"../../escape"`,
		`"with/slash"`,
		`"with:colon"`,
		`"UpperCase"`,
		`"-leading-dash"`,
		`"trailing-dash-"`,
		`"with space"`,
		`""`,
		strings.Repeat("a", maxNameLength+1),
	}
	for _, name := range invalid {
		_, err := FromYAML(tpWithName(name))
		require.Error(t, err, "name %q should be rejected", name)
		require.Contains(t, err.Error(), "metadata.name")
	}
}
