// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"io/ioutil"

	"github.com/isovalent/tetragon-oss/pkg/k8s/apis/isovalent.com/v1alpha1"
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

func ReadConfigYaml(data string) (*GenericTracingConf, error) {
	var k GenericTracingConf

	err := yaml.UnmarshalStrict([]byte(data), &k)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func fileConfig(fileName string) (*GenericTracingConf, error) {
	config, err := ioutil.ReadFile(fileName)
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
