// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
// Copyright Orange

package tracing

import (
	"testing"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
)

func TestBuildBtfArgFromLSMPolicy(t *testing.T) {
	rawPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm"
spec:
  lsmhooks:
  - hook: "fake"
    args:
    - index: 0
      type: "linux_binprm"
      extractParam: 'mm.arg_start'
      overwriteType: 'int'
    - index: 1
      type: "linux_binprm"
      extractParam: 'file.f_path.dentry.d_name.name'
      overwriteType: 'string'
  `
	policy, err := tracingpolicy.FromYAML(rawPolicy)
	assert.NoError(t, err, "FromYAML rawPolicy error %s", err)

	var btfArgs [api.EventConfigMaxArgs][api.MaxBtfArgDepth]api.ConfigBtfArg

	for i, arg := range policy.TpSpec().LsmHooks[0].Args {
		btfArgs[i] = [api.MaxBtfArgDepth]api.ConfigBtfArg{}
		lastBtfType, err := buildBtfArg(arg, &btfArgs[i])
		assert.NoError(t, err)
		assert.NotEqual(t, nil, lastBtfType)
		argType := findTypeFromBtfType(arg, lastBtfType)
		assert.NotEqual(t, gt.GenericInvalidType, argType, "Type %s is not supported", (*lastBtfType).TypeName())
	}

	result := [api.EventConfigMaxArgs][api.MaxBtfArgDepth]api.ConfigBtfArg{
		[api.MaxBtfArgDepth]api.ConfigBtfArg{
			{Offset: 16, IsPointer: 1, IsInitialized: 1},
			{Offset: 368, IsPointer: 1, IsInitialized: 1},
		},
		[api.MaxBtfArgDepth]api.ConfigBtfArg{
			{Offset: 64, IsPointer: 1, IsInitialized: 1},
			{Offset: 152, IsPointer: 0, IsInitialized: 1},
			{Offset: 8, IsPointer: 1, IsInitialized: 1},
			{Offset: 32, IsPointer: 0, IsInitialized: 1},
			{Offset: 8, IsPointer: 1, IsInitialized: 1},
		},
	}
	assert.Equal(t, btfArgs, result)
}
