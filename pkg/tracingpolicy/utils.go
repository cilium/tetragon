// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"path/filepath"
	"strings"
)

// sanitize removes the characters that policyDir() and
// collectionKey.String() use as separators, so that a policy component
// cannot inject structure into the string it is embedded in.
func sanitize(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	return strings.ReplaceAll(name, ":", "_")
}

// policyDir derives the bpffs directory for a policy from its full identity
// (domain, namespace, name). All three components are part of the sensor
// manager's collection key, so all three must be part of the pin path:
// otherwise same-name policies from different domains (k8s, grpc, static,
// ...) resolve to the same directory and silently share or destroy each
// other's pinned policy-scoped maps (policy_conf, policy_selectors_stats,
// enforcer_data).
//
// Empty components are omitted, mirroring collectionKey.String(), so
// cluster-scoped policies get "k8s:name" rather than "k8s::name" and
// sensors with no owning policy keep their legacy flat layout. Collection
// keys cannot contain ":" or "/", so for any policy (which always has a
// non-empty domain) the mapping from identity to directory is 1:1.
func policyDir(domain, namespace, policyName string) string {
	parts := make([]string, 0, 3)
	for _, part := range []string{domain, namespace, policyName} {
		if part != "" {
			parts = append(parts, sanitize(part))
		}
	}
	return strings.Join(parts, ":")
}

// PolicyDir returns the directory of the policy in tetragon's bpf fs hierearchy
func PolicyDir(domain, namespace, policyName string) string {
	return filepath.Join(policyDir(domain, namespace, policyName))
}
