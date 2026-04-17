// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"path/filepath"
	"strings"
)

func sanitize(name string) string {
	return strings.ReplaceAll(name, "/", "_")
}

func policyDir(namespace, policyName string) string {
	if namespace == "" {
		return sanitize(policyName)
	}
	return fmt.Sprintf("%s:%s", namespace, sanitize(policyName))
}

// PolicyDir returns the directory of the policy in tetragon's bpf fs hierearchy
func PolicyDir(namespace, policyName string) string {
	return filepath.Join(policyDir(namespace, policyName))
}
