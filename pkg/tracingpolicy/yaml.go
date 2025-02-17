// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v2"
)

func specSetMode(spec map[interface{}]interface{}, mode string) error {
	optsRaw, hasOpts := spec["options"]
	if !hasOpts { // if there are no options, just add them
		spec["options"] = []map[string]string{
			{"name": "policy-mode", "value": mode},
		}
		return nil
	}

	opts, optsOK := optsRaw.([]interface{})
	if !optsOK {
		return fmt.Errorf("spec.options has unexpected type: %T", optsRaw)
	}

	var newOpts = []interface{}{}
	for i := range opts {
		optRaw := opts[i]
		opt, optOK := optRaw.(map[interface{}]interface{})
		if !optOK {
			return fmt.Errorf("spec.options[%d] has unexpected type: %T", i, optRaw)
		}

		optMap := make(map[string]interface{})
		for optKeyRaw, optValRaw := range opt {
			optKey, optKeyOk := optKeyRaw.(string)
			if !optKeyOk {
				return fmt.Errorf("spec.options[%d] key has unexpected type: %T", i, optKeyRaw)
			}
			optMap[optKey] = optValRaw
		}

		nameVal := optMap["name"]
		if nameVal != "policy-mode" {
			newOpts = append(newOpts, optRaw)
		}
	}

	spec["options"] = append(newOpts, map[interface{}]interface{}{
		"name":  "policy-mode",
		"value": mode,
	})

	return nil
}

// PolicyYAMLSetMode modifies a yaml file to set the mode of the policy
func PolicyYAMLSetMode(data []byte, mode string) ([]byte, error) {
	m := make(map[interface{}]interface{})
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	switch mode {
	case "":
		return yaml.Marshal(m)
	case "enforce", "monitor":
	default:
		return nil, fmt.Errorf("invalid mode: %q", mode)
	}

	specRaw, hasSpec := m["spec"]
	if !hasSpec {
		return nil, errors.New("yaml does not include spec section")
	}

	spec, specOK := specRaw.(map[interface{}]interface{})
	if !specOK {
		return nil, fmt.Errorf("spec has unexpected type: %T", specRaw)
	}

	if err := specSetMode(spec, mode); err != nil {
		return nil, err
	}

	return yaml.Marshal(m)
}
