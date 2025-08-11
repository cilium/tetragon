// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// This file contains test helpers that couldn't be included in testutils
// package because of cyclic dependencies.

package crdutils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// TPContext and GenericTracingPolicy replicate definitions from tracingpolicy
// package as examples to test generic functionality.

var TPContext, _ = NewCRDContext[*GenericTracingPolicy](&client.TracingPolicyCRD.Definition)

type GenericTracingPolicy struct {
	metav1.TypeMeta
	Metadata metav1.ObjectMeta          `json:"metadata"`
	Spec     v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicy) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &gtp.Metadata
}

// Read a template file and apply data to it, returning the resulting string
func ReadFileTemplate(fileName string, data any) (string, error) {
	templ, err := template.ParseFiles(fileName)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = templ.Execute(&buf, data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func FileConfigWithTemplate(fileName string, data any) (*GenericTracingPolicy, error) {
	polyaml, err := ReadFileTemplate(fileName, data)
	if err != nil {
		return nil, err
	}

	pol, err := TPContext.FromYAML(polyaml)
	if err != nil {
		return nil, fmt.Errorf("TPContext.FromYAML error %w", err)
	}
	return pol, nil
}

func CheckPolicies(t *testing.T, policiesDir string, fromFile func(string) error) {
	err := filepath.Walk(policiesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-yaml files
		if info.IsDir() || (!strings.HasSuffix(info.Name(), "yaml") && !strings.HasSuffix(info.Name(), "yml")) {
			return nil
		}

		// Attempt to parse the file
		err = fromFile(path)
		require.NoError(t, err, "example %s must parse correctly: %s", info.Name(), err)

		return nil
	})
	require.NoError(t, err, "failed to walk examples directory")
}

func CreateTempFile(t *testing.T, data string) string {
	file, err := os.CreateTemp(t.TempDir(), "tetragon-")
	if err != nil {
		t.Fatalf("cannot create temp. file: %v", err)
	}
	_, err = file.WriteString(data)
	if err != nil {
		t.Fatalf("cannot write to temp. file: %v", err)
	}
	err = file.Close()
	if err != nil {
		t.Fatalf("cannot close temp. file: %v", err)
	}
	return file.Name()
}
