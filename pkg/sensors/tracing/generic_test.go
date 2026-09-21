// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// TestFormatBTFPathValid tests that formatBTFPath tokenizes valid resolve
// paths.
func TestFormatBTFPathValid(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		// standalone paths
		{input: "field", want: []string{"field"}},
		{input: "path.to.my.field", want: []string{"path", "to", "my", "field"}},

		// arrays
		{input: "[0]", want: []string{"[0]"}},
		{input: "[1].path.to.field", want: []string{"[1]", "path", "to", "field"}},
		{input: "[0][1].field", want: []string{"[0]", "[1]", "field"}},
		{input: "path.to[123].my.field", want: []string{"path", "to", "[123]", "my", "field"}},
		{input: "field[1][2]", want: []string{"field", "[1]", "[2]"}},

		// simple casts
		{input: "(char**)field", want: []string{"field", "(char**)"}},
		{input: "(struct task_struct *)field", want: []string{"field", "(struct task_struct *)"}},

		// casts with arrays
		{input: "(char*)field[0]", want: []string{"field", "[0]", "(char*)"}},
		{input: "(char*)(field[0])", want: []string{"field", "[0]", "(char*)"}},
		{input: "(char*)(field)[0]", want: []string{"field", "[0]", "(char*)"}},
		{input: "((char*)field)[16]", want: []string{"field", "(char*)", "[16]"}},

		// cast as head of the resolve path
		{input: "(char*)field[123].my.sub.field", want: []string{"field", "[123]", "my", "sub", "field", "(char*)"}},

		// nested casts
		{
			input: "((struct task_struct*)((struct my_struct**)((char*)field)[8])[2]).comm",
			want:  []string{"field", "(char*)", "[8]", "(struct my_struct**)", "[2]", "(struct task_struct*)", "comm"},
		},

		// cast mid-path
		{input: "path.((char*)target)[8].end", want: []string{"path", "target", "(char*)", "[8]", "end"}},
		{
			input: "my.super.((struct my_struct**)((char*)field)[123]).my.sub.field",
			want:  []string{"my", "super", "field", "(char*)", "[123]", "(struct my_struct**)", "my", "sub", "field"},
		},
		{
			input: "path.to[1].((struct my_struct**)((char*)target)[8])[2].my.end",
			want:  []string{"path", "to", "[1]", "target", "(char*)", "[8]", "(struct my_struct**)", "[2]", "my", "end"},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := formatBTFPath(test.input)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

// TestFormatBTFPathInvalid tests that formatBTFPath rejects malformed resolve
// paths.
func TestFormatBTFPathInvalid(t *testing.T) {
	inputs := []string{
		// empty segments
		"",
		".field",
		"field.",
		"my..field",

		// the index must be a decimal uint32, and an array binds directly to
		// what precedes it, never across a dot
		"field[]",
		"field[123",
		"field.123]",
		"field[[123]]",
		"field[.123]",
		"field.[123]",
		"field[-1]",

		// cast types
		"()(field)", // empty type
		"(char*",    // unclosed paren

		// a cast takes exactly one target and only arrays may follow it
		"(char*)",                      // missing target
		"(char*)()",                    // empty target
		"(char*)(field",                // unclosed target paren
		"(char*)(field)abc",            // trailing characters
		"(char*)(field)((char*)field)", // trailing expression
		"((char*))(field)",             // trailing expression after a grouped cast
		"(char*)(char*)field",          // cast applied to a cast

		// a cast that does not open the path must be grouped, ((type*)target),
		// as only that form says where its operand ends
		"path.(char*)target.end",
		"path.(char*)(target)",

		// identifiers hold no parens or brackets of their own
		"rsp(char*)[16]",
		"(char*)field)", // unbalanced closing paren
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			_, err := formatBTFPath(input)
			require.Error(t, err)
		})
	}
}

// This test attempt to test the Resolve flag in tracing policies.
//   - The 2 first hooks assert no error occures when searching for the BTF config
//   - The last test is used to assert an error occures when path length is
//     higher than api.MaxBTFArgDepth
func TestResolveBTFArgFromKprobePolicy(t *testing.T) {
	rawPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kprobes"
spec:
  kprobes:
  - call: "security_bprm_check"
    args:
    - index: 0
      type: "int"
      resolve: 'mm.arg_start'
  - call: "security_inode_copy_up"
    args:
    - index: 0
      type: "uint32"
      resolve: 'd_flags'
    - index: 1
      type: "int"
      resolve: 'user.uid.val'
  - call: "do_pipe2"
    args:
    - index: 0
      resolve: "[0]"
      type: int
      label: "pipefd[0]"
    - index: 0
      resolve: "[1]"
      type: int
      label: "pipefd[1]"
  - call: "security_bprm_check"
    args:
    - index: 0
      type: "string"
      resolve: 'mm.owner.real_parent.real_parent.real_parent.real_parent.real_parent.real_parent.real_parent.real_parent.comm'
  `
	policy, err := tracingpolicy.FromYAML(rawPolicy)
	require.NoError(t, err, "FromYAML rawPolicy error %q", err)

	successHook := policy.TpSpec().KProbes[:3]
	for _, hook := range successHook {
		for _, arg := range hook.Args {
			lastBTFType, btfArg, err := resolveBTFArg(hook.Call, &arg, false, nil)
			if err != nil {
				t.Fatal(hook.Call, err)
			}
			require.NotNil(t, lastBTFType)
			assert.NotNil(t, btfArg)

			argType := findTypeFromBTFType(&arg, lastBTFType)
			require.NotEqual(t, gt.GenericInvalidType, argType, "Type %q is not supported", (*lastBTFType).TypeName())
		}
	}

	failHook := policy.TpSpec().KProbes[3]
	for _, arg := range failHook.Args {
		_, _, err := resolveBTFArg(failHook.Call, &arg, false, nil)

		require.ErrorContains(t, err, "The maximum depth allowed is", "The path %q must have len < %d", arg.Resolve, api.MaxBTFArgDepth)
	}
}

func TestResolveBTFArgWithBTFType(t *testing.T) {
	rawPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kprobes"
spec:
  kprobes:
  - call: "security_socket_connect"
    args:
    - index: 1
      type: "uint16"
      label: "sockaddr.sa_family"
      btfType: "sockaddr"
      resolve: "sa_family"
    - index: 1
      type: "uint8"
      label: "sockaddr.sa_data[0]"
      btfType: "sockaddr"
      resolve: "sa_data[0]"
    - index: 1
      type: "uint16"
      label: "sockaddr_in.sin_port"
      btfType: "sockaddr_in"
      resolve: "sin_port"
    - index: 1
      type: "uint32"
      label: "sockaddr_in.sin_addr.s_addr"
      btfType: "sockaddr_in"
      resolve: "sin_addr.s_addr"
    - index: 1
      type: "uint8"
      label: "sockaddr_un.sun_path[0]"
      btfType: "sockaddr_un"
      resolve: "sun_path[0]"
    - index: 1
      type: "uint16"
      label: "sockaddr_un.sun_family"
      btfType: "sockaddr_un"
      resolve: "sun_family"
  `
	policy, err := tracingpolicy.FromYAML(rawPolicy)
	require.NoError(t, err, "FromYAML rawPolicy error %q", err)

	tests := map[string]struct {
		wantType  int
		wantDepth int
	}{
		"sockaddr.sa_family":          {gt.GenericU16Type, 1},
		"sockaddr.sa_data[0]":         {gt.GenericU8Type, 2},
		"sockaddr_in.sin_port":        {gt.GenericU16Type, 1},
		"sockaddr_in.sin_addr.s_addr": {gt.GenericU32Type, 2},
		"sockaddr_un.sun_path[0]":     {gt.GenericU8Type, 2},
		"sockaddr_un.sun_family":      {gt.GenericU16Type, 1},
	}

	for _, hook := range policy.TpSpec().KProbes {
		for _, arg := range hook.Args {
			test, ok := tests[arg.Label]
			require.True(t, ok, "missing test case for %q", arg.Label)

			t.Run(arg.Label, func(t *testing.T) {
				lastBTFType, btfArg, err := resolveBTFArg(hook.Call, &arg, false, nil)
				require.NoError(t, err, hook.Call)
				require.NotNil(t, lastBTFType)

				argType := findTypeFromBTFType(&arg, lastBTFType)
				require.Equal(t, test.wantType, argType, "Type %q is not supported", (*lastBTFType).TypeName())

				for i, entry := range btfArg {
					if i < test.wantDepth {
						require.Equal(t, uint16(1), entry.IsInitialized, "BTF arg depth %d", i)
						continue
					}
					require.Zero(t, entry.IsInitialized, "BTF arg depth %d", i)
				}
			})
		}
	}
}

func TestResolveBTFArgWithBTFTypeModule(t *testing.T) {
	arg := v1alpha1.KProbeArg{
		Index:         1,
		Type:          "uint16",
		BTFType:       "sockaddr_un",
		BTFTypeModule: "tetragon_test_module_that_does_not_exist",
		Resolve:       "sun_family",
	}

	_, _, err := resolveBTFArg("security_socket_connect", &arg, false, nil)
	require.ErrorContains(t, err, `failed to find BTF type "sockaddr_un" in module "tetragon_test_module_that_does_not_exist"`)
}

func TestAppendMacrosSelectors(t *testing.T) {
	tests := map[string]struct {
		selectors         []v1alpha1.KProbeSelector
		macros            map[string]v1alpha1.KProbeSelector
		expectedSelectors []v1alpha1.KProbeSelector
		expectErr         bool
	}{
		"correct macro usage": {
			selectors: []v1alpha1.KProbeSelector{
				{
					MatchBinaries: []v1alpha1.BinarySelector{
						{
							Operator: "In",
							Values:   []string{"bin"},
						},
					},
					Macros: []string{"testMacro"},
				},
			},
			macros: map[string]v1alpha1.KProbeSelector{
				"testMacro": {
					Label: "macro-label",
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    0,
							Operator: "In",
							Values:   []string{"arg-1"},
						},
					},
				},
			},
			expectedSelectors: []v1alpha1.KProbeSelector{
				{
					Label: "macro-label",
					MatchBinaries: []v1alpha1.BinarySelector{
						{
							Operator: "In",
							Values:   []string{"bin"},
						},
					},
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    0,
							Operator: "In",
							Values:   []string{"arg-1"},
						},
					},
					Macros: []string{"testMacro"},
				},
			},
		},
		"non-existent macro": {
			selectors: []v1alpha1.KProbeSelector{
				{
					Macros: []string{"wrongMacro"},
				},
			},
			macros: map[string]v1alpha1.KProbeSelector{
				"testMacro": {
					MatchBinaries: []v1alpha1.BinarySelector{
						{
							Operator: "In",
							Values:   []string{"bin"},
						},
					},
				},
			},
			expectErr: true,
		},
		"use of macro in macro": {
			selectors: []v1alpha1.KProbeSelector{
				{
					Macros: []string{"testMacro"},
				},
			},
			macros: map[string]v1alpha1.KProbeSelector{
				"testMacro": {
					Macros: []string{"otherMacro"},
					MatchBinaries: []v1alpha1.BinarySelector{
						{
							Operator: "In",
							Values:   []string{"bin"},
						},
					},
				},
			},
			expectErr: true,
		},
		"same field in macro and in selector": {
			selectors: []v1alpha1.KProbeSelector{
				{
					MatchBinaries: []v1alpha1.BinarySelector{
						{
							Operator: "In",
							Values:   []string{"bin"},
						},
					},
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    0,
							Operator: "In",
							Values:   []string{"arg-1"},
						},
					},
					Macros: []string{"testMacro"},
				},
			},
			macros: map[string]v1alpha1.KProbeSelector{
				"testMacro": {
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    1,
							Operator: "In",
							Values:   []string{"arg-2"},
						},
					},
				},
			},
			expectErr: true,
		},
		"same field in different macros": {
			selectors: []v1alpha1.KProbeSelector{
				{
					MatchBinaries: []v1alpha1.BinarySelector{
						{
							Operator: "In",
							Values:   []string{"bin"},
						},
					},
					Macros: []string{"testMacro1", "testMacro2"},
				},
			},
			macros: map[string]v1alpha1.KProbeSelector{
				"testMacro1": {
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    0,
							Operator: "In",
							Values:   []string{"arg-1"},
						},
					},
				},
				"testMacro2": {
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    1,
							Operator: "In",
							Values:   []string{"arg-2"},
						},
					},
				},
			},
			expectErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := appendMacrosSelectors(test.selectors, test.macros)
			if test.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expectedSelectors, test.selectors)
			}
		})
	}
}
