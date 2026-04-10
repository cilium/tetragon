// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultAnnKeys mirrors the production default for annotation namespace keys.
var defaultAnnKeys = []string{
	"io.kubernetes.pod.namespace",
	"io.kubernetes.cri.sandbox-namespace",
}

// Namespace name constants used across tests.
const (
	nsKubeSystem = "kube-system"
	nsDefault    = "default"
	nsMonitor    = "monitoring"

	// Glob pattern examples.
	patternAcme = "acme-*"
	patternDev  = "dev-*"
)

// helpers ----------------------------------------------------------------

func celUserExprNoError(t *testing.T, expr string) *celProg {
	t.Helper()
	ret, err := celUserExpr(expr)
	require.NoError(t, err)
	return ret
}

func celAllowNamespacesNoError(t *testing.T, namespaces, patterns []string) *celProg {
	t.Helper()
	cliConf.AnnNamespaceKeys = defaultAnnKeys
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

// -----------------------------------------------------------------------
// TestCelAllowNamespaces - original exact-match behaviour
// -----------------------------------------------------------------------

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
			name:        "namespace in allow list (sandbox-namespace key) - allow",
			namespaces:  []string{nsKubeSystem},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "namespace in allow list (pod.namespace key) - allow",
			namespaces:  []string{nsKubeSystem},
			annotations: annPod(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "multiple allowed namespaces - match second - allow",
			namespaces:  []string{nsKubeSystem, nsMonitor},
			annotations: ann(nsMonitor),
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

// -----------------------------------------------------------------------
// TestCelAllowNamespacesWithPatternsOnly - pattern-only mode
// -----------------------------------------------------------------------

func TestCelAllowNamespacesWithPatternsOnly(t *testing.T) {
	tests := []struct {
		name        string
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
			name:        "irrelevant annotation key - fail",
			patterns:    []string{patternAcme},
			annotations: map[string]string{"some.other.key": "acme-foo"},
			wantFail:    true,
		},
		{
			name:        "namespace matches pattern - allow",
			patterns:    []string{patternAcme},
			annotations: ann("acme-foo"),
			wantFail:    false,
		},
		{
			name:        "namespace does NOT match pattern - fail",
			patterns:    []string{patternAcme},
			annotations: ann("foo-acme"),
			wantFail:    true,
		},
		{
			name:        "namespace matches one of multiple patterns - allow",
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("dev-backend"),
			wantFail:    false,
		},
		{
			name:        "namespace does not match any pattern - fail",
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("backend-dev"),
			wantFail:    true,
		},
		{
			name:        "prefix wildcard - kube-system matches kube-* - allow",
			patterns:    []string{"kube-*"},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "prefix wildcard - kube-system-foo matches kube-* - allow",
			patterns:    []string{"kube-*"},
			annotations: ann("kube-system-foo"),
			wantFail:    false,
		},
		{
			name:        "suffix wildcard - cert-manager-system matches *-system - allow",
			patterns:    []string{"*-system"},
			annotations: ann("cert-manager-system"),
			wantFail:    false,
		},
		{
			name:        "suffix wildcard - kube-system-foo does NOT match *-system - fail",
			patterns:    []string{"*-system"},
			annotations: ann("kube-system-foo"),
			wantFail:    true,
		},
		{
			name:        "pod.namespace annotation key also checked - allow",
			patterns:    []string{patternDev},
			annotations: annPod("dev-backend"),
			wantFail:    false,
		},
		{
			name:        "empty patterns slice - fail for any namespace",
			patterns:    []string{},
			annotations: ann(nsKubeSystem),
			wantFail:    true,
		},
		{
			name:        "bare wildcard * - matches any namespace - allow",
			patterns:    []string{"*"},
			annotations: ann("any-namespace"),
			wantFail:    false,
		},
		{
			name:        "contains wildcard - foo-*-bar matches foo-anything-bar - allow",
			patterns:    []string{"foo-*-bar"},
			annotations: ann("foo-anything-bar"),
			wantFail:    false,
		},
		{
			name:        "contains wildcard - foo-*-bar does NOT match foo-bar - fail",
			patterns:    []string{"foo-*-bar"},
			annotations: ann("foo-bar"),
			wantFail:    true,
		},
		{
			name:        "exact pattern without wildcard - matches exactly - allow",
			patterns:    []string{nsKubeSystem},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "exact pattern without wildcard - does NOT match different ns - fail",
			patterns:    []string{nsKubeSystem},
			annotations: ann("kube-system-foo"),
			wantFail:    true,
		},
		{
			name:        "empty string pattern - does NOT match any real namespace - fail",
			patterns:    []string{""},
			annotations: ann(nsKubeSystem),
			wantFail:    true,
		},
		{
			name:        "overlapping patterns - * and kube-* - namespace matched by both - allow",
			patterns:    []string{"*", "kube-*"},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "overlapping patterns - ku* and kube* - namespace matched by both - allow",
			patterns:    []string{"ku*", "kube*"},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "overlapping patterns - ku* and kube* - namespace matched by first only - allow",
			patterns:    []string{"ku*", "kube*"},
			annotations: ann("ku-foo"),
			wantFail:    false,
		},
		{
			name:        "overlapping patterns - * wildcard allows namespace not matched by other pattern - allow",
			patterns:    []string{"kube-*", "*"},
			annotations: ann("unrelated-namespace"),
			wantFail:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := celAllowNamespacesNoError(t, nil, tc.patterns)
			assert.Equal(t, tc.wantFail, runCheck(t, checker, tc.annotations))
		})
	}
}

// -----------------------------------------------------------------------
// TestCelAllowNamespacesCombined - exact namespaces + patterns together
// -----------------------------------------------------------------------

func TestCelAllowNamespacesCombined(t *testing.T) {
	tests := []struct {
		name        string
		namespaces  []string
		patterns    []string
		annotations map[string]string
		wantFail    bool
	}{
		{
			name:        "no annotations - fail (safe default)",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: nil,
			wantFail:    true,
		},
		{
			name:        "namespace matches first pattern - allow",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("acme-foo"),
			wantFail:    false,
		},
		{
			name:        "namespace has pattern as suffix only - fail",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("foo-acme"),
			wantFail:    true,
		},
		{
			name:        "namespace matches second pattern - allow",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("dev-backend"),
			wantFail:    false,
		},
		{
			name:        "namespace has second pattern as suffix only - fail",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("backend-dev"),
			wantFail:    true,
		},
		{
			name:        "namespace matches exact entry - allow",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "namespace is a superset of exact entry - fail",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("kube-system-foo"),
			wantFail:    true,
		},
		{
			name:        "arbitrary unrelated namespace - fail",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: ann("foo"),
			wantFail:    true,
		},
		{
			name:        "pod.namespace annotation key also honoured - allow",
			namespaces:  []string{nsKubeSystem},
			patterns:    []string{patternAcme, patternDev},
			annotations: annPod(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "namespace in exact list but not matching any pattern - allow",
			namespaces:  []string{nsMonitor},
			patterns:    []string{patternDev},
			annotations: ann(nsMonitor),
			wantFail:    false,
		},
		{
			name:        "namespace matches pattern but not in exact list - allow",
			namespaces:  []string{nsMonitor},
			patterns:    []string{patternDev},
			annotations: ann("dev-backend"),
			wantFail:    false,
		},
		{
			name:        "namespace in neither exact list nor patterns - fail",
			namespaces:  []string{nsMonitor},
			patterns:    []string{patternDev},
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

// -----------------------------------------------------------------------
// TestCelAllowNamespacesWithPatternsInvalidGlob - error handling
// -----------------------------------------------------------------------

func TestCelAllowNamespacesWithPatternsInvalidGlob(t *testing.T) {
	cliConf.AnnNamespaceKeys = defaultAnnKeys
	tests := []struct {
		name    string
		pattern string
	}{
		{name: "two wildcards separated", pattern: "a*b*c"},
		{name: "two wildcards adjacent", pattern: "a**b"},
		{name: "wildcard at both ends", pattern: "*foo*"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := celAllowNamespacesWithPatterns(nil, []string{tc.pattern})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid namespace pattern")
		})
	}
}

// -----------------------------------------------------------------------
// TestCelUserExpr - custom CEL expression (existing behaviour, extended)
// -----------------------------------------------------------------------

func TestCelUserExpr(t *testing.T) {
	cliConf.AnnNamespaceKeys = defaultAnnKeys

	// celExprWithPatterns demonstrates --fail-cel-expr with a hand-written CEL
	// expression that uses built-in .matches() (regex) for prefix checks.
	// This is distinct from --fail-allow-namespaces-patterns, which uses globs.
	celExprWithPatterns := `!(annotations.exists(k, k in ["io.kubernetes.pod.namespace",` +
		`"io.kubernetes.cri.sandbox-namespace"] && (annotations[k] == "kube-system" ||` +
		`annotations[k].matches("^acme-") ||` +
		`annotations[k].matches("^dev-"))))`

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
			name:        "CEL expr with patterns - matching first pattern - allow",
			expr:        celExprWithPatterns,
			annotations: ann("acme-foo"),
			wantFail:    false,
		},
		{
			name:        "CEL expr with patterns - pattern as suffix only - fail",
			expr:        celExprWithPatterns,
			annotations: ann("foo-acme"),
			wantFail:    true,
		},
		{
			name:        "CEL expr with patterns - matching second pattern - allow",
			expr:        celExprWithPatterns,
			annotations: ann("dev-backend"),
			wantFail:    false,
		},
		{
			name:        "CEL expr with patterns - second pattern as suffix only - fail",
			expr:        celExprWithPatterns,
			annotations: ann("backend-dev"),
			wantFail:    true,
		},
		{
			name:        "CEL expr with patterns - exact namespace - allow",
			expr:        celExprWithPatterns,
			annotations: ann(nsKubeSystem),
			wantFail:    false,
		},
		{
			name:        "CEL expr with patterns - superset of exact namespace - fail",
			expr:        celExprWithPatterns,
			annotations: ann("kube-system-foo"),
			wantFail:    true,
		},
		{
			name:        "CEL expr with patterns - unrelated namespace - fail",
			expr:        celExprWithPatterns,
			annotations: ann("foo"),
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

// -----------------------------------------------------------------------
// TestAnnotationKeyPriority - first matching key wins
// -----------------------------------------------------------------------

func TestAnnotationKeyPriority(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantFail    bool
	}{
		{
			name: "first key allowed, second key would fail - allow",
			annotations: map[string]string{
				"io.kubernetes.pod.namespace":         nsKubeSystem,
				"io.kubernetes.cri.sandbox-namespace": nsDefault,
			},
			wantFail: false,
		},
		{
			name: "first key fails, second key would allow - fail",
			annotations: map[string]string{
				"io.kubernetes.pod.namespace":         nsDefault,
				"io.kubernetes.cri.sandbox-namespace": nsKubeSystem,
			},
			wantFail: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := celAllowNamespacesNoError(t, []string{nsKubeSystem}, nil)
			assert.Equal(t, tc.wantFail, runCheck(t, checker, tc.annotations))
		})
	}
}

// -----------------------------------------------------------------------
// TestCheckersConstructableWhenRthooksDisabled - construction edge cases
// When rthooks are disabled (DisableGrpc path) the fail check is never
// reached, but the checkers must still be constructable without error.
// -----------------------------------------------------------------------

func TestCheckersConstructableWhenRthooksDisabled(t *testing.T) {
	cliConf.AnnNamespaceKeys = defaultAnnKeys

	tests := []struct {
		name       string
		namespaces []string
		patterns   []string
		wantFail   bool // result when checking a real namespace
	}{
		{
			name:       "celAllowNamespaces with no namespaces",
			namespaces: []string{},
			patterns:   nil,
			wantFail:   true,
		},
		{
			name:       "celAllowNamespacesWithPatterns with no args - fail for any ns",
			namespaces: nil,
			patterns:   nil,
			wantFail:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := celAllowNamespacesNoError(t, tc.namespaces, tc.patterns)
			assert.Equal(t, tc.wantFail, runCheck(t, checker, ann(nsKubeSystem)))
		})
	}
}
