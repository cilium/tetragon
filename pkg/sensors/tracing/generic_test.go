// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	gt "github.com/cilium/tetragon/pkg/generictypes"
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
  - call: "security_bprm_check"
    args:
    - index: 0
      type: "string"
      resolve: 'mm.owner.real_parent.real_parent.real_parent.real_parent.real_parent.real_parent.real_parent.real_parent.comm'
  `
	policy, err := tracingpolicy.FromYAML(rawPolicy)
	require.NoError(t, err, "FromYAML rawPolicy error %q", err)

	successHook := policy.TpSpec().KProbes[:2]
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

	failHook := policy.TpSpec().KProbes[2]
	for _, arg := range failHook.Args {
		_, _, err := resolveBTFArg(failHook.Call, &arg, false)

		require.ErrorContains(t, err, "The maximum depth allowed is", "The path %q must have len < %d", arg.Resolve, api.MaxBTFArgDepth)
	}
}
