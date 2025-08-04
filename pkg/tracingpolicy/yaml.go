// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func specSetMode(spec map[string]any, mode string) error {
	optsRaw, hasOpts := spec["options"]
	if !hasOpts { // if there are no options, just add them
		spec["options"] = []map[string]string{
			{"name": "policy-mode", "value": mode},
		}
		return nil
	}

	opts, optsOK := optsRaw.([]any)
	if !optsOK {
		return fmt.Errorf("spec.options has unexpected type: %T", optsRaw)
	}

	var newOpts = []any{}
	for i := range opts {
		optRaw := opts[i]
		opt, optOK := optRaw.(map[string]any)
		if !optOK {
			return fmt.Errorf("spec.options[%d] has unexpected type: %T", i, optRaw)
		}

		if opt["name"] != "policy-mode" {
			newOpts = append(newOpts, optRaw)
		}
	}

	spec["options"] = append(newOpts, map[string]any{
		"name":  "policy-mode",
		"value": mode,
	})

	return nil
}

// PolicyYAMLSetMode modifies a yaml file to set the mode of the policy
func PolicyYAMLSetMode(data []byte, mode string) ([]byte, error) {
	m := unstructured.Unstructured{}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	switch mode {
	case "":
		return yaml.Marshal(m.Object)
	case "enforce", "monitor":
	default:
		return nil, fmt.Errorf("invalid mode: %q", mode)
	}

	specRaw, hasSpec := m.Object["spec"]
	if !hasSpec {
		return nil, errors.New("yaml does not include spec section")
	}

	spec, specOK := specRaw.(map[string]any)
	if !specOK {
		return nil, fmt.Errorf("spec has unexpected type: %T", specRaw)
	}

	if err := specSetMode(spec, mode); err != nil {
		return nil, err
	}

	return yaml.Marshal(m.Object)
}
