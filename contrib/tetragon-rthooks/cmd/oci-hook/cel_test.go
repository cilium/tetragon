// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Namespace name constants used across tests.
const (
	nsKubeSystem = "kube-system"
	nsDefault    = "default"
	nsMonitor    = "monitoring"

	// RE2 regex pattern examples. Anchored with ^ and $ for full-string matching.
	patternAcme = "^acme-.*$"
	patternDev  = "^dev-.*$"
)

func celUserExprNoError(t *testing.T, expr string) *celProg {
	t.Helper()
	ret, err := celUserExpr(expr)
	require.NoError(t, err)
	return ret
}

func celAllowNamespacesNoError(t *testing.T, namespaces, patterns []string) *celProg {
	t.Helper()
	cliConf.AnnNamespaceKeys = defaultAnnotationsNamespaceKeys
	ret, err := celAllowNamespacesWithPatterns(namespaces, patterns)
	require.NoError(t, err)
	return ret
}

// runCheck is a small wrapper to call RunFailCheck and assert no error.
func runCheck(t *testing.T, checker *celProg, annotations map[string]string) bool {
	t.Helper()
	result, err := checker.RunFailCheck(annotations)
	require.NoError(t, err)
	return result
}

// ann builds an annotation map with the containerd sandbox-namespace key.
func ann(ns string) map[string]string {
	return map[string]string{"io.kubernetes.cri.sandbox-namespace": ns}
}

// annPod builds an annotation map with the pod.namespace key (cri-o style).
func annPod(ns string) map[string]string {
	return map[string]string{"io.kubernetes.pod.namespace": ns}
}

// TestCelAllowNamespaces - exact-match behaviour
func TestCelAllowNamespaces(t *testing.T) {
	tests := []struct {
		name        string
		namespaces  []string
		annotations map[string]string
		wantFail    bool
	}{
		{
			name:        "no annotations - fail (safe default)",
			namespaces:  []string{nsKubeSystem},
			annotations: nil,
			wantFail:    true,
		},
		{
			name:        "irrelevant annotation key - fail",
			namespaces:  []string{nsKubeSystem},
			annotations: map[string]string{"some.other.key": nsKubeSystem},
			wantFail:    true,
		},
		{
			name:        "namespace not in allow list - fail",
			namespaces:  []string{nsKubeSystem},
			annotations: ann(nsDefault),
			wantFail:    true,
		},
		{
			name:        "namespace in allow list (containerd key) - allow",
			namespaces:  []string{nsKubeSystem},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "namespace in allow list (cri-o key) - allow",
			namespaces:  []string{nsKubeSystem},
			annotations: annPod(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "empty allow list - fail for any namespace",
			namespaces:  []string{},
			annotations: ann(nsKubeSystem),
			wantFail:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := celAllowNamespacesNoError(t, tc.namespaces, nil)
			assert.Equal(t, tc.wantFail, runCheck(t, checker, tc.annotations))
		})
	}
}

// TestCelAllowNamespacesWithPatterns - regex pattern behaviour
func TestCelAllowNamespacesWithPatterns(t *testing.T) {
	tests := []struct {
		name        string
		namespaces  []string
		patterns    []string
		annotations map[string]string
		wantFail    bool
	}{
		{
			name:        "no annotations - fail (safe default)",
			patterns:    []string{patternAcme},
			annotations: nil,
			wantFail:    true,
		},
		{
			name:        "namespace matches pattern - allow",
			patterns:    []string{patternAcme},
			annotations: ann("acme-foo"),
			wantFail:    false,
		},
		{
			name:        "namespace does not match any pattern - fail",
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("other-ns"),
			wantFail:    true,
		},
		{
			name:        "empty patterns - fail for any namespace",
			patterns:    []string{},
			annotations: ann(nsKubeSystem),
			wantFail:    true,
		},
		{
			name:        "exact namespace in list - allow",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "namespace matches pattern but not exact list - allow",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme},
			annotations: ann("acme-foo"),
			wantFail:    false,
		},
		{
			name:        "namespace matches neither exact list nor pattern - fail",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme},
			annotations: ann(nsDefault),
			wantFail:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := celAllowNamespacesNoError(t, tc.namespaces, tc.patterns)
			assert.Equal(t, tc.wantFail, runCheck(t, checker, tc.annotations))
		})
	}
}

// TestAnnotationKeyPriority - all keys must allow; any failing key fails
func TestAnnotationKeyPriority(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantFail    bool
	}{
		{
			name: "first key allowed, second key would fail - fail (all keys must allow)",
			annotations: map[string]string{
				"io.kubernetes.pod.namespace":         nsKubeSystem,
				"io.kubernetes.cri.sandbox-namespace": nsDefault,
			},
			wantFail: true,
		},
		{
			name: "both keys allowed - allow",
			annotations: map[string]string{
				"io.kubernetes.pod.namespace":         nsKubeSystem,
				"io.kubernetes.cri.sandbox-namespace": nsKubeSystem,
			},
			wantFail: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := celAllowNamespacesNoError(t, []string{nsKubeSystem}, nil)
			assert.Equal(t, tc.wantFail, runCheck(t, checker, tc.annotations))
		})
	}
}

// TestCelUserExpr - custom CEL expression via --fail-cel-expr
func TestCelUserExpr(t *testing.T) {
	cliConf.AnnNamespaceKeys = defaultAnnotationsNamespaceKeys

	tests := []struct {
		name        string
		expr        string
		annotations map[string]string
		wantFail    bool
	}{
		{
			name:        "expr always true - fail",
			expr:        "true",
			annotations: nil,
			wantFail:    true,
		},
		{
			name:        "expr always false - allow",
			expr:        "false",
			annotations: nil,
			wantFail:    false,
		},
		{
			// Validates that users can write their own CEL expressions using .matches()
			// as an alternative to --fail-allow-namespaces-regex.
			name: "user-written CEL with .matches() - matching namespace - allow",
			expr: `!(annotations.exists(k, k in ["io.kubernetes.pod.namespace",
				"io.kubernetes.cri.sandbox-namespace"] && annotations[k].matches("^acme-.*$")))`,
			annotations: ann("acme-foo"),
			wantFail:    false,
		},
		{
			name: "user-written CEL with .matches() - non-matching namespace - fail",
			expr: `!(annotations.exists(k, k in ["io.kubernetes.pod.namespace",
				"io.kubernetes.cri.sandbox-namespace"] && annotations[k].matches("^acme-.*$")))`,
			annotations: ann("other-ns"),
			wantFail:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := celUserExprNoError(t, tc.expr)
			assert.Equal(t, tc.wantFail, runCheck(t, checker, tc.annotations))
		})
	}
}
