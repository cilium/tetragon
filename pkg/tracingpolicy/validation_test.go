// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// maxNameLength is the DNS-1123 subdomain limit, applied to metadata.name by
// apimachinery in k8s builds and by validateObjectName in non-k8s builds.
const maxNameLength = 253

func TestFromYAMLNameValidation(t *testing.T) {
	tpWithName := func(name string) string {
		return fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %s
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
`, name)
	}

	valid := []string{
		"my-policy",
		"policy.with.dots",
		"p",
		`"0123"`,
		strings.Repeat("a", maxNameLength),
	}
	for _, name := range valid {
		_, err := FromYAML(tpWithName(name))
		require.NoError(t, err, "name %q should be accepted", name)
	}

	invalid := []string{
		`".."`,
		`"."`,
		`"../../escape"`,
		`"with/slash"`,
		`"with:colon"`,
		`"UpperCase"`,
		`"-leading-dash"`,
		`"trailing-dash-"`,
		`"with space"`,
		`""`,
		strings.Repeat("a", maxNameLength+1),
	}
	for _, name := range invalid {
		_, err := FromYAML(tpWithName(name))
		require.Error(t, err, "name %q should be rejected", name)
		require.Contains(t, err.Error(), "metadata.name")
	}
}
