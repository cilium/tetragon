// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"text/template"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/stretchr/testify/assert"
)

var writev = `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "sys_write"
    return: false
    syscall: true
    args:
      - index: 0
        type: "int"
      - index: 1
        type: "char_buf"
        sizeArgIndex: 3
      - index: 2
        type: "size_t"
    selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          isNamespacePID: false
          values:
            - 1
        matchArgs:
        - index: 0
          operator: "equal"
          values:
            - "1"
        matchNamespaces:
        - namespace: Net
          operator: In
          values:
            - "4026532024"
            - "4026532025"
        - namespace: Mnt
          operator: NotIn
          values:
            - "4026532099"
        matchNamespaceChanges:
        - operator: In
          values:
          - "Mnt"
          - "Pid"
          - "User"
          - "Uts"
        matchCapabilities:
        - type: Effective
          operator: In
          isNamespaceCapability: true
          values:
            - "CAP_CHOWN"
            - "CAP_NET_RAW"
        - type: Inheritable
          operator: NotIn
          values:
            - "CAP_SETPCAP"
            - "CAP_SYS_ADMIN"
        matchCapabilityChanges:
        - type: Effective
          operator: In
          isNamespaceCapability: true
          values:
            - "CAP_SYS_ADMIN"
            - "CAP_NET_RAW"
`

var expectedWrite = GenericTracingConf{
	ApiVersion: "cilium.io/v1alpha1",
	Metadata:   Metadata{Name: "sys-write"},
	Spec: v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call:    "sys_write",
				Return:  false,
				Syscall: true,
				Args: []v1alpha1.KProbeArg{
					{
						Index: 0,
						Type:  "int",
					},
					{
						Index:        1,
						Type:         "char_buf",
						SizeArgIndex: 3,
					},
					{
						Index: 2,
						Type:  "size_t",
					},
				},
				Selectors: []v1alpha1.KProbeSelector{
					{
						MatchPIDs: []v1alpha1.PIDSelector{
							{
								Operator:       "In",
								Values:         []uint32{1},
								FollowForks:    true,
								IsNamespacePID: false,
							},
						},
						MatchArgs: []v1alpha1.ArgSelector{
							{
								Index:    0,
								Operator: "equal",
								Values:   []string{"1"},
							},
						},
						MatchNamespaces: []v1alpha1.NamespaceSelector{
							{
								Namespace: "Net",
								Operator:  "In",
								Values:    []string{"4026532024", "4026532025"},
							},
							{
								Namespace: "Mnt",
								Operator:  "NotIn",
								Values:    []string{"4026532099"},
							},
						},
						MatchNamespaceChanges: []v1alpha1.NamespaceChangesSelector{
							{
								Operator: "In",
								Values:   []string{"Mnt", "Pid", "User", "Uts"},
							},
						},
						MatchCapabilities: []v1alpha1.CapabilitiesSelector{
							{
								Type:                  "Effective",
								Operator:              "In",
								IsNamespaceCapability: true,
								Values:                []string{"CAP_CHOWN", "CAP_NET_RAW"},
							},
							{
								Type:                  "Inheritable",
								Operator:              "NotIn",
								IsNamespaceCapability: false,
								Values:                []string{"CAP_SETPCAP", "CAP_SYS_ADMIN"},
							},
						},
						MatchCapabilityChanges: []v1alpha1.CapabilitiesSelector{
							{
								Type:                  "Effective",
								Operator:              "In",
								IsNamespaceCapability: true,
								Values:                []string{"CAP_SYS_ADMIN", "CAP_NET_RAW"},
							},
						},
					},
				},
			},
		},
	},
}

var data = `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "example_func"
    return: true
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
    - index: 2
      type: "int"
    - index: 3
      type: "string"
    - index: 4
      type: "skb"
  - call: "another_func"
    return: false
    syscall: false
    args:
    - index: 0
      type: "string"
    - index: 1
      type: "string"
    - index: 2
      type: "string"
    - index: 3
      type: "string"
    selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          isNamespacePID: false
          values:
            - 1
            - 2
        matchArgs:
        - index: 0
          operator: "equal"
          values:
            - "1"
        - index: 1
          operator: "notequal"
          values:
            - "world"
        matchNamespaces:
        - namespace: Pid
          operator: In
          values:
          - 4026532024
        matchNamespaceChanges:
        - operator: In
          values:
          - "Mnt"
          - "Pid"
          - "Net"
        matchCapabilities:
        - type: Effective
          operator: In
          isNamespaceCapability: true
          values:
            - "CAP_SYS_ADMIN"
        matchCapabilityChanges:
        - type: Effective
          operator: In
          isNamespaceCapability: true
          values:
            - "CAP_SYS_ADMIN"
`

var expectedData = GenericTracingConf{
	ApiVersion: "cilium.io/v1alpha1",
	Metadata:   Metadata{Name: "sys-write"},
	Spec: v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call:    "example_func",
				Return:  true,
				Syscall: true,
				Args: []v1alpha1.KProbeArg{
					{
						Index: 0,
						Type:  "int",
					},
					{
						Index: 1,
						Type:  "int",
					},
					{
						Index: 2,
						Type:  "int",
					},
					{
						Index: 3,
						Type:  "string",
					},
					{
						Index: 4,
						Type:  "skb",
					},
				},
			},
			{
				Call:    "another_func",
				Return:  false,
				Syscall: false,
				Args: []v1alpha1.KProbeArg{
					{
						Index: 0,
						Type:  "string",
					},
					{
						Index: 1,
						Type:  "string",
					},
					{
						Index: 2,
						Type:  "string",
					},
					{
						Index: 3,
						Type:  "string",
					},
				},
				Selectors: []v1alpha1.KProbeSelector{
					{
						MatchPIDs: []v1alpha1.PIDSelector{
							{
								Operator:       "In",
								Values:         []uint32{1, 2},
								FollowForks:    true,
								IsNamespacePID: false,
							},
						},
						MatchArgs: []v1alpha1.ArgSelector{
							{
								Index:    0,
								Operator: "equal",
								Values:   []string{"1"},
							},
							{
								Index:    1,
								Operator: "notequal",
								Values:   []string{"world"},
							},
						},
						MatchNamespaces: []v1alpha1.NamespaceSelector{
							{
								Namespace: "Pid",
								Operator:  "In",
								Values:    []string{"4026532024"},
							},
						},
						MatchNamespaceChanges: []v1alpha1.NamespaceChangesSelector{
							{
								Operator: "In",
								Values:   []string{"Mnt", "Pid", "Net"},
							},
						},
						MatchCapabilities: []v1alpha1.CapabilitiesSelector{
							{
								Type:                  "Effective",
								Operator:              "In",
								IsNamespaceCapability: true,
								Values:                []string{"CAP_SYS_ADMIN"},
							},
						},
						MatchCapabilityChanges: []v1alpha1.CapabilitiesSelector{
							{
								Type:                  "Effective",
								Operator:              "In",
								IsNamespaceCapability: true,
								Values:                []string{"CAP_SYS_ADMIN"},
							},
						},
					},
				},
			},
		},
	},
}

func TestYamlWritev(t *testing.T) {
	k, err := ReadConfigYaml(writev)
	if err != nil {
		t.Errorf("YamlWritev error %s", err)
	}
	if reflect.DeepEqual(*k, expectedWrite) != true {
		t.Errorf("not equal\nk=%v\ne= %v\n", k, expectedWrite)
	}
}

func TestYamlData(t *testing.T) {
	k, err := ReadConfigYaml(data)
	if err != nil {
		t.Errorf("YamlData error %s", err)
	}
	if reflect.DeepEqual(*k, expectedData) != true {
		t.Errorf("not equal\nk=%v\ne= %v\n", k, expectedData)
	}
}

//go:embed examples/tracepoint-lseek-pid.yaml
var lseekExample string

func TestYamlLseek(t *testing.T) {

	expected := GenericTracingConf{
		ApiVersion: "cilium.io/v1alpha1",
		Metadata:   Metadata{Name: "tracepoint-lseek"},
		Spec: v1alpha1.TracingPolicySpec{
			Tracepoints: []v1alpha1.TracepointSpec{{
				Subsystem: "syscalls",
				Event:     "sys_enter_lseek",
				Args: []v1alpha1.KProbeArg{
					{Index: 7},
					{Index: 5},
				},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchPIDs: []v1alpha1.PIDSelector{
						{
							Operator:       "eq",
							FollowForks:    true,
							IsNamespacePID: false,
							Values:         []uint32{1111},
						},
					},
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    7,
							Operator: "eq",
							Values:   []string{"4444"},
						},
					},
				}},
			}},
		},
	}

	k, err := ReadConfigYaml(lseekExample)
	if err != nil {
		t.Errorf("ReadConfigYaml failed: %s", err)
	}

	if reflect.DeepEqual(expected, *k) != true {
		t.Errorf("\ngot:\n%+v\nexpected:\n%+v", *k, expected)
	}
}

// Read a config file and sub in templated values
func fileConfigWithTemplate(fileName string, data interface{}) (*GenericTracingConf, error) {
	templ, err := template.ParseFiles(fileName)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	templ.Execute(&buf, data)

	return ReadConfigYaml(buf.String())
}

func TestExamplesSmoke(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../examples/tracingpolicy")
	err := filepath.Walk(examplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-directories
		if info.IsDir() {
			return nil
		}

		// Skip non-yaml files with a warning
		if !strings.HasSuffix(info.Name(), "yaml") || strings.HasSuffix(info.Name(), "yml") {
			logger.GetLogger().WithField("path", path).Warn("skipping non-yaml file")
			return nil
		}

		// Fill this in with template data as needed
		data := map[string]string{
			"Pid": fmt.Sprint(os.Getpid()),
		}

		// Attempt to parse the file
		_, err = fileConfigWithTemplate(path, data)
		assert.NoError(t, err, "example %s must parse correctly", info.Name())

		return nil
	})

	assert.NoError(t, err, "failed to walk examples directory")
}

const invalidNameYaml = `apiVersion: cilium.io/v1alpha1
metadata:
  name: "invalid_name"`

func TestReadConfigYamlInvalidName(t *testing.T) {
	_, err := ReadConfigYaml(invalidNameYaml)
	assert.Error(t, err)
}
