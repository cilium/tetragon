// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

type Metadata struct {
	Name string `yaml:"name"`
}

type GenericTracingConf struct {
	ApiVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   Metadata                   `json:"metadata"`
	Spec       v1alpha1.TracingPolicySpec `json:"spec"`
}

func (cnf *GenericTracingConf) TpName() string {
	return cnf.Metadata.Name
}

func (cnf *GenericTracingConf) TpSpec() *v1alpha1.TracingPolicySpec {
	return &cnf.Spec
}

func (cnf *GenericTracingConf) TpInfo() string {
	return cnf.Metadata.Name
}

func PolicyFromYaml(data string) (tracingpolicy.TracingPolicy, error) {
	var k GenericTracingConf

	err := yaml.UnmarshalStrict([]byte(data), &k)
	// if yaml file contains a namespace field, parsing will fail. Retry
	// again to parse it as a namespaced policy.
	if err != nil {
		return NamespacedPolicyFromYaml(data)
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

func PolicyFromYamlFilename(fileName string) (tracingpolicy.TracingPolicy, error) {
	config, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return PolicyFromYaml(string(config))
}

type MetadataNamespaced struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

type GenericTracingConfNamespaced struct {
	ApiVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   MetadataNamespaced         `json:"metadata"`
	Spec       v1alpha1.TracingPolicySpec `json:"spec"`
}

func (cnf *GenericTracingConfNamespaced) TpNamespace() string {
	return cnf.Metadata.Namespace
}

func (cnf *GenericTracingConfNamespaced) TpName() string {
	return cnf.Metadata.Name
}

func (cnf *GenericTracingConfNamespaced) TpSpec() *v1alpha1.TracingPolicySpec {
	return &cnf.Spec
}

func (cnf *GenericTracingConfNamespaced) TpInfo() string {
	return cnf.Metadata.Name
}

func NamespacedPolicyFromYaml(data string) (tracingpolicy.TracingPolicy, error) {
	var k GenericTracingConfNamespaced

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
