// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package tracingpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/nok8s"
)

// dns1123SubdomainMaxLength is the maximum length of a DNS-1123 subdomain, as
// enforced by k8s.io/apimachinery.
const dns1123SubdomainMaxLength = 253

// dns1123SubdomainRegexp mirrors apimachinery's IsDNS1123Subdomain, which the
// k8s build applies to metadata.name through ValidateObjectMeta.
var dns1123SubdomainRegexp = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// validateObjectName applies the same metadata.name rules as the k8s build.
// The embedded JSON schema does not describe metadata, so without this check
// non-k8s builds would accept arbitrary names (e.g. ".." or names containing
// path or key separators) that end up in bpffs pin paths.
func validateObjectName(name string) error {
	if name == "" {
		return errors.New("metadata.name: required value")
	}
	if len(name) > dns1123SubdomainMaxLength {
		return fmt.Errorf("metadata.name: invalid value %q: must be no more than %d characters", name, dns1123SubdomainMaxLength)
	}
	if !dns1123SubdomainRegexp.MatchString(name) {
		return fmt.Errorf("metadata.name: invalid value %q: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character", name)
	}
	return nil
}

// FromYAML parses a YAML string into a TracingPolicy -- !k8s version
func FromYAML(data string) (TracingPolicy, error) {
	kind, jsonBytes, err := nok8s.ParseK8sObj(data)
	if err != nil {
		return nil, err
	}

	switch kind {
	case v1alpha1.TPKindDefinition:
		var gtp GenericTracingPolicy
		if err := json.Unmarshal(jsonBytes, &gtp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TracingPolicy: %w", err)
		}

		if err := validateObjectName(gtp.Metadata.Name); err != nil {
			return nil, fmt.Errorf("failed to validate TracingPolicy: %w", err)
		}

		return &gtp, nil
	case v1alpha1.TPNamespacedKindDefinition:
		return nil, fmt.Errorf("namespaced tracing policies not supported in non-k8s builds: %s", kind)
	default:
		return nil, fmt.Errorf("unknown kind: %s", kind)
	}
}
