// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func celUserExprNoError(t *testing.T, expr string) *celProg {
	ret, err := celUserExpr(expr)
	require.NoError(t, err)
	return ret
}

func celAllowNamespacesNoError(t *testing.T, vals []string) *celProg {
	ret, err := celAllowNamespaces(vals)
	require.NoError(t, err)
	return ret
}

func TestCel(t *testing.T) {
	type testCase struct {
		prog        *celProg
		expectedVal interface{}
		annotations map[string]string
	}
	testCases := []testCase{
		{prog: celUserExprNoError(t, "true"), expectedVal: true},
		// expected value true: program will fail because annotations do not include namespace key
		{prog: celAllowNamespacesNoError(t, []string{"kube-system"}), expectedVal: true},
		// expected value true: program will fail because namespace is default
		{prog: celAllowNamespacesNoError(t, []string{"kube-system"}), expectedVal: true, annotations: map[string]string{
			"io.kubernetes.pod.namespace": "default",
		}},
		// expected value false: program will not fail because namespace is kube-system
		{prog: celAllowNamespacesNoError(t, []string{"root", "kube-system"}), expectedVal: false, annotations: map[string]string{
			"io.kubernetes.pod.namespace": "kube-system",
		}},
		// expected value false: program will not fail because namespace is kube-system
		{prog: celAllowNamespacesNoError(t, []string{"root", "kube-system"}), expectedVal: false, annotations: map[string]string{
			"io.kubernetes.cri.sandbox-namespace": "kube-system",
		}},
	}

	for _, tc := range testCases {
		ret, err := tc.prog.RunFailCheck(tc.annotations)
		require.NoError(t, err)
		require.Equal(t, tc.expectedVal, ret)
	}
}
