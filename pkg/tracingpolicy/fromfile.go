// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import "os"

// FromFile loads a CRD object from a YAML file at the given path.
func FromFile(path string) (TracingPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromYAML(string(data))
}
