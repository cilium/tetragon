// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package k8s

import (
	"strings"
)

// ParseNamespaceName returns the object's namespace and name. If namespace is
// not specified, the namespace "default" is returned.
func ParseNamespaceName(namespaceName string) (string, string) {
	nsName := strings.Split(namespaceName, "/")
	ns := nsName[0]
	switch {
	case len(nsName) > 1:
		return ns, nsName[1]
	case ns == "":
		return "", ""
	default:
		return "default", ns
	}
}

// ParseNamespaceNames returns the object's namespace and name. If namespace is
// not specified, the namespace "default" is returned.
func ParseNamespaceNames(namespaceNames []string) ([]string, []string) {
	pods := make([]string, 0, len(namespaceNames))
	nss := make([]string, 0, len(namespaceNames))

	for _, namespaceName := range namespaceNames {
		ns, pod := ParseNamespaceName(namespaceName)
		nss = append(nss, ns)
		pods = append(pods, pod)
	}

	return nss, pods
}
