// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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
	return fmt.Sprintf("%s", cnf.Metadata.Name)
}

func ReadConfigYaml(data string) (*GenericTracingConf, error) {
	var k GenericTracingConf

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

func fileConfig(fileName string) (*GenericTracingConf, error) {
	config, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ReadConfigYaml(string(config))
}

func FileConfigSpec(fileName string) (*v1alpha1.TracingPolicySpec, error) {
	k, err := fileConfig(fileName)
	if err != nil {
		return nil, err
	}
	return &k.Spec, err
}

func FileConfigYaml(fileName string) (*GenericTracingConf, error) {
	return fileConfig(fileName)
}
