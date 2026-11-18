// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestUprobeArgConfigPtRegsCasts(t *testing.T) {
	if !bpf.HasProgramLargeSize() {
		t.Skip("need large BPF programs")
	}

	reg, reg32 := "rsp", "eax"
	if runtime.GOARCH == "arm64" {
		reg, reg32 = "sp", "w0"
	}

	btfPath := writeRegisterPayloadBTF(t)

	tests := []struct {
		name    string
		btfPath string
		resolve string
		want    [api.MaxBTFArgDepth]api.ConfigBTFArg
		wantErr string
	}{
		{
			name:    "primitive without BTF",
			resolve: reg + ".as(uint64 ***)[0][0][9]",
			want: [api.MaxBTFArgDepth]api.ConfigBTFArg{
				{IsPointer: 1, IsInitialized: 1},
				{IsPointer: 1, IsInitialized: 1},
				{Offset: 72, IsPointer: 1, IsInitialized: 1},
			},
		},
		{
			name:    "named type with BTF",
			btfPath: btfPath,
			resolve: reg + ".as(struct register_payload *).value",
			want: [api.MaxBTFArgDepth]api.ConfigBTFArg{
				{Offset: 8, IsPointer: 1, IsInitialized: 1},
			},
		},
		{
			name:    "field through pointer to pointer",
			btfPath: btfPath,
			resolve: reg + ".as(struct register_payload **).value",
			want: [api.MaxBTFArgDepth]api.ConfigBTFArg{
				{IsPointer: 1, IsInitialized: 1},
				{Offset: 8, IsPointer: 1, IsInitialized: 1},
			},
		},
		{
			name:    "non-pointer cast",
			btfPath: btfPath,
			resolve: reg + ".as(struct register_payload).value",
			wantErr: "a register can only be cast to a pointer type",
		},
		{
			name:    "non-pointer array cast",
			resolve: reg + ".as(uint64[4])[2]",
			wantErr: "a register can only be cast to a pointer type",
		},
		{
			name:    "no cast on register",
			resolve: reg + "[0]",
			wantErr: "a register must be cast to a pointer type",
		},
		{
			name:    "narrow register",
			resolve: reg32 + ".as(uint64 *)[0]",
			wantErr: "only 64-bit registers can be resolved through",
		},
		{
			name:    "named type without BTF",
			resolve: reg + ".as(struct register_payload *).value",
			wantErr: "no BTF spec provided",
		},
		{
			name:    "no kernel BTF fallback",
			btfPath: btfPath,
			resolve: reg + ".as(struct task_struct *).pid",
			wantErr: `failed to resolve struct "task_struct"`,
		},
		{
			name:    "cast without access",
			resolve: reg + ".as(uint64 *)",
			wantErr: "must be followed by a field or an index",
		},
		{
			name:    "invalid BTF path",
			btfPath: btfPath + ".missing",
			resolve: reg + ".as(struct register_payload *).value",
			wantErr: "failed to load user BTF spec",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := getUprobeArgConfig(&v1alpha1.UProbeSpec{
				BTFPath: tt.btfPath,
				Data: []v1alpha1.KProbeArg{{
					Type:    "uint64",
					Source:  "pt_regs",
					Resolve: tt.resolve,
				}},
			}, &uprobeHas{})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.allBTFArgs[0])
			require.Equal(t, uint8(8), cfg.regArg[0].Size)
		})
	}
}

// writeRegisterPayloadBTF writes a BTF file holding struct register_payload,
// which has a uint64 value at offset 8, and returns its path.
func writeRegisterPayloadBTF(t *testing.T) string {
	t.Helper()
	builder, err := btf.NewBuilder([]btf.Type{&btf.Struct{
		Name: "register_payload",
		Size: 16,
		Members: []btf.Member{{
			Name:   "value",
			Type:   &btf.Int{Name: "uint64", Size: 8},
			Offset: 64,
		}},
	}}, nil)
	require.NoError(t, err)
	raw, err := builder.Marshal(nil, nil)
	require.NoError(t, err)
	btfPath := filepath.Join(t.TempDir(), "register.btf")
	require.NoError(t, os.WriteFile(btfPath, raw, 0o600))
	return btfPath
}

func TestUprobeArgConfigRootCasts(t *testing.T) {
	btfPath := writeRegisterPayloadBTF(t)

	tests := []struct {
		name    string
		resolve string
		want    [api.MaxBTFArgDepth]api.ConfigBTFArg
		wantErr string
	}{
		{
			name:    "pointer cast",
			resolve: "as(struct register_payload *).value",
			want: [api.MaxBTFArgDepth]api.ConfigBTFArg{
				{Offset: 8, IsPointer: 1, IsInitialized: 1},
			},
		},
		{
			// The argument points to a pointer, which needs a dereference of
			// its own before the field is read.
			name:    "pointer to pointer cast",
			resolve: "as(struct register_payload **).value",
			want: [api.MaxBTFArgDepth]api.ConfigBTFArg{
				{IsPointer: 1, IsInitialized: 1},
				{Offset: 8, IsPointer: 1, IsInitialized: 1},
			},
		},
		{
			name:    "non-pointer cast",
			resolve: "as(struct register_payload).value",
			wantErr: "the argument can only be cast to a pointer type",
		},
		{
			// This would only report the argument value under another type.
			name:    "cast without access",
			resolve: "as(uint64 *)",
			wantErr: "a cast on the argument must be followed by a field or an index",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := getUprobeArgConfig(&v1alpha1.UProbeSpec{
				BTFPath: btfPath,
				Args: []v1alpha1.KProbeArg{{
					Type:    "uint64",
					BTFType: "register_payload",
					Resolve: tt.resolve,
				}},
			}, &uprobeHas{})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.allBTFArgs[0])
		})
	}
}

func TestUprobeArgConfigLoadsUserBTFLazily(t *testing.T) {
	reg := "rdi"
	if runtime.GOARCH == "arm64" {
		reg = "x0"
	}
	missing := filepath.Join(t.TempDir(), "missing.btf")

	// Nothing reads the user BTF, so an unreadable btfPath is not an error.
	_, err := getUprobeArgConfig(&v1alpha1.UProbeSpec{
		BTFPath: missing,
		Args:    []v1alpha1.KProbeArg{{Type: "uint64"}},
		Data:    []v1alpha1.KProbeArg{{Type: "uint64", Source: "pt_regs", Resolve: reg}},
	}, &uprobeHas{})
	require.NoError(t, err)

	_, err = getUprobeArgConfig(&v1alpha1.UProbeSpec{
		BTFPath: missing,
		Args: []v1alpha1.KProbeArg{{
			Type:    "uint64",
			BTFType: "register_payload",
			Resolve: "value",
		}},
	}, &uprobeHas{})
	require.ErrorContains(t, err, "failed to load user BTF spec")
}

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	var state uprobeConfigState
	err := initUprobeArgs(&v1alpha1.UProbeSpec{}, &uprobeHas{}, &addUprobeIn{policyID: 7}, &state)
	require.NoError(t, err)
	require.Equal(t, uint32(7), state.eventConfig.PolicyID)
}

// The enforcer actions are only implemented for kprobes and tracepoints, so
// they have to be rejected here rather than silently do nothing.
func TestUprobeValidationEnforcerAction(t *testing.T) {
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-notify-enforcer"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols: ["main"]
    selectors:
    - matchActions:
      - action: NotifyEnforcer
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enforcer actions are not supported")
}

func TestUprobeValidationStackTraceRequiresPost(t *testing.T) {
	tests := []struct {
		name       string
		action     v1alpha1.ActionSelector
		wantErrMsg string
	}{
		{
			name: "kernel stack with Post action",
			action: v1alpha1.ActionSelector{
				Action:           "Post",
				KernelStackTrace: true,
			},
			wantErrMsg: "kernelStackTrace is not supported for uprobes",
		},
		{
			name: "user stack with non-Post action",
			action: v1alpha1.ActionSelector{
				Action:         "NoPost",
				UserStackTrace: true,
			},
			wantErrMsg: "userStackTrace can only be used along Post action",
		},
		{
			name: "user stack with Post action",
			action: v1alpha1.ActionSelector{
				Action:         "Post",
				UserStackTrace: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := &v1alpha1.UProbeSpec{
				Symbols: []string{"main"},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchActions: []v1alpha1.ActionSelector{test.action},
				}},
			}

			err := validateUprobeSpec(spec, &uprobeConfigState{})
			if test.wantErrMsg != "" {
				require.ErrorContains(t, err, test.wantErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUprobeValidationOverrideMultipleSymbols(t *testing.T) {
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-multi-override-new-symbol-so-two-targets"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols:
    - "first_target"
    - "second_target"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_first_target
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "only a single uprobe symbol can be redirected")
}
