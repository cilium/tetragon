// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

type Metadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations"`
}

type GenericTracingPolicy struct {
	ApiVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   Metadata                   `json:"metadata"`
	Spec       v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicy) TpName() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicy) TpAnnotations() map[string]string {
	return gtp.Metadata.Annotations
}

func (gtp *GenericTracingPolicy) TpHasAnnotation(ann string) bool {
	annotations := gtp.TpAnnotations()
	_, found := annotations[ann]
	return found
}

func (gtp *GenericTracingPolicy) TpSpec() *v1alpha1.TracingPolicySpec {
	return &gtp.Spec
}

func (gtp *GenericTracingPolicy) TpInfo() string {
	return gtp.Metadata.Name
}

func PolicyFromYAML(data string) (TracingPolicy, error) {
	var k GenericTracingPolicy

	err := yaml.UnmarshalStrict([]byte(data), &k)
	// if yaml file contains a namespace field, parsing will fail. Retry
	// again to parse it as a namespaced policy.
	if err != nil {
		return NamespacedPolicyFromYAML(data)
	}

	// validates that metadata.name value is compliant with RFC 1123 for the
	// object to be a valid Kubernetes object, see:
	// https://k8s.io/docs/concepts/overview/working-with-objects/names/
	errs := validation.IsDNS1123Subdomain(k.Metadata.Name)
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid metadata.name value %q: %s", k.Metadata.Name, strings.Join(errs, ","))
	}

	return &k, nil
}

func PolicyFromYAMLFilename(fileName string) (TracingPolicy, error) {
	policy, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return PolicyFromYAML(string(policy))
}

type MetadataNamespaced struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Annotations map[string]string `yaml:"annotations"`
}

type GenericTracingPolicyNamespaced struct {
	ApiVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   MetadataNamespaced         `json:"metadata"`
	Spec       v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicyNamespaced) TpNamespace() string {
	return gtp.Metadata.Namespace
}

func (gtp *GenericTracingPolicyNamespaced) TpName() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicyNamespaced) TpAnnotations() map[string]string {
	return gtp.Metadata.Annotations
}

func (gtp *GenericTracingPolicyNamespaced) TpHasAnnotation(ann string) bool {
	annotations := gtp.TpAnnotations()
	_, found := annotations[ann]
	return found
}

func (gtp *GenericTracingPolicyNamespaced) TpSpec() *v1alpha1.TracingPolicySpec {
	return &gtp.Spec
}

func (gtp *GenericTracingPolicyNamespaced) TpInfo() string {
	return gtp.Metadata.Name
}

func NamespacedPolicyFromYAML(data string) (TracingPolicy, error) {
	var k GenericTracingPolicyNamespaced

	err := yaml.UnmarshalStrict([]byte(data), &k)
	if err != nil {
		return nil, err
	}

	// validates that metadata.name value is compliant with RFC 1123 for the
	// object to be a valid Kubernetes object, see:
	// https://k8s.io/docs/concepts/overview/working-with-objects/names/
	errs := validation.IsDNS1123Subdomain(k.Metadata.Name)
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid metadata.name value %q: %s", k.Metadata.Name, strings.Join(errs, ","))
	}

	return &k, nil
}
