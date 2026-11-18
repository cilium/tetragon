// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"runtime"
	"testing"

	ebtf "github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestFormatBTFPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:    "simple resolve path",
			input:   "path.to.my.field",
			want:    []string{"path", "to", "my", "field"},
			wantErr: false,
		},
		{
			name:    "array as first resolve",
			input:   "[1].path.to.my.field",
			want:    []string{"[1]", "path", "to", "my", "field"},
			wantErr: false,
		},
		{
			name:    "array in the resolve path",
			input:   "path.to[123].my.field",
			want:    []string{"path", "to", "[123]", "my", "field"},
			wantErr: false,
		},
		{
			name:    "dot inside bracket",
			input:   "my.super.field[.123]",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "empty bracket",
			input:   "my.super.field[].my.sub.field",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "dot before bracket",
			input:   "my.super.field.[123].my.sub.field",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "consecutive dots",
			input:   "my..field",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "unclosed bracket",
			input:   "my.field[123",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "unopened bracket",
			input:   "my.field.123]",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "nested brackets",
			input:   "my.field[[123]]",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "empty path",
			input:   "",
			want:    []string{},
			wantErr: true,
		},
		{
			// Accepted for compatibility with the parser before casts.
			name:    "leading dot",
			input:   ".my.field",
			want:    []string{"my", "field"},
			wantErr: false,
		},
		{
			// Accepted for compatibility with the parser before casts.
			name:    "trailing dot",
			input:   "my.field.",
			want:    []string{"my", "field"},
			wantErr: false,
		},
		{
			name:    "leading and trailing dot",
			input:   ".my.field[0].",
			want:    []string{"my", "field", "[0]"},
			wantErr: false,
		},
		{
			name:    "only a dot",
			input:   ".",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "two leading dots",
			input:   "..my.field",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "two trailing dots",
			input:   "my.field..",
			want:    []string{},
			wantErr: true,
		},
		{
			// Accepted for compatibility with the parser before casts.
			name:    "identifier right after index",
			input:   "my.field[0]sub[1]leaf.x",
			want:    []string{"my", "field", "[0]", "sub", "[1]", "leaf", "x"},
			wantErr: false,
		},
		{
			name:    "cast right after index",
			input:   "my.field[0]as(char *)[1]",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "negative index",
			input:   "my.field[-1]",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "parenthesis in identifier",
			input:   "my(field)[123]",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "cast at start",
			input:   "as(char **).field",
			want:    []string{"as(char **)", "field"},
			wantErr: false,
		},
		{
			name:    "cast at end",
			input:   "field.as(struct task_struct *)",
			want:    []string{"field", "as(struct task_struct *)"},
			wantErr: false,
		},
		{
			name:    "cast followed by index",
			input:   "field.as(char *)[16]",
			want:    []string{"field", "as(char *)", "[16]"},
			wantErr: false,
		},
		{
			name:    "multiple casts",
			input:   "field.as(char *)[8].as(struct task_struct *).comm",
			want:    []string{"field", "as(char *)", "[8]", "as(struct task_struct *)", "comm"},
			wantErr: false,
		},
		{
			name:    "empty cast",
			input:   "as()",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "unclosed cast",
			input:   "as(char *",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "identifier after cast",
			input:   "as(char *)field",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "junk after cast",
			input:   "field.as(char *)junk",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "unbalanced cast parenthesis",
			input:   "field.as(char *))",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "parenthesis in cast type",
			input:   "field.as(int (*)(void))",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "cast without as",
			input:   "field.(char *)",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "consecutive casts at end",
			input:   "field.as(char *).as(int32 *)",
			want:    []string{},
			wantErr: true,
		},
		{
			name:    "consecutive casts at start",
			input:   "as(char *).as(int32 *).field",
			want:    []string{},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ret, err := formatBTFPath(test.input)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.want, ret)
			}
		})
	}
}

func TestBTFPathDepthDoesNotCountCasts(t *testing.T) {
	path, err := formatBTFPath("field.as(char *)[8].as(struct task_struct *).comm")
	require.NoError(t, err)
	assert.Equal(t, 3, btf.PathDepth(path))
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
			lastBTFType, btfArg, err := resolveBTFArg(hook.Call, &arg, false)
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
		_, _, err := resolveBTFArg(failHook.Call, &arg, false)

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
				lastBTFType, btfArg, err := resolveBTFArg(hook.Call, &arg, false)
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

	_, _, err := resolveBTFArg("security_socket_connect", &arg, false)
	require.ErrorContains(t, err, `failed to find BTF type "sockaddr_un" in module "tetragon_test_module_that_does_not_exist"`)
}

// TestResolvePtRegsArgKernelBTFCast checks that a register cast can name a
// kernel type when given the kernel BTF, as kprobes do.
func TestResolvePtRegsArgKernelBTFCast(t *testing.T) {
	if !bpf.HasProgramLargeSize() {
		t.Skip("need large BPF programs")
	}

	reg := "rdi"
	if runtime.GOARCH == "arm64" {
		reg = "x0"
	}

	spec, err := btf.NewBTF()
	require.NoError(t, err)
	var task *ebtf.Struct
	require.NoError(t, spec.TypeByName("task_struct", &task))
	var pid *ebtf.Member
	for i := range task.Members {
		if task.Members[i].Name == "pid" {
			pid = &task.Members[i]
		}
	}
	require.NotNil(t, pid, "task_struct has no direct pid member")

	_, btfArg, hasBTFArg, err := resolvePtRegsArg(reg+".as(struct task_struct *).pid", func() (*ebtf.Spec, error) { return spec, nil })
	require.NoError(t, err)
	require.True(t, hasBTFArg)
	require.Equal(t, [api.MaxBTFArgDepth]api.ConfigBTFArg{
		{Offset: pid.Offset.Bytes(), IsPointer: 1, IsInitialized: 1},
	}, btfArg)

	_, _, _, err = resolvePtRegsArg(reg+".as(struct task_struct *).pid", func() (*ebtf.Spec, error) { return nil, nil })
	require.ErrorContains(t, err, "no BTF spec provided")
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
