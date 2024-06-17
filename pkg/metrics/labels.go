// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import "github.com/prometheus/client_golang/prometheus"

// ConstrainedLabel represents a label with constrained cardinality.
// Values is a list of all possible values of the label.
type ConstrainedLabel struct {
	Name   string
	Values []string
}

// UnconstrainedLabel represents a label with unconstrained cardinality.
// ExampleValue is an example value of the label used for documentation.
type UnconstrainedLabel struct {
	Name         string
	ExampleValue string
}

func stringToUnconstrained(labels []string) []UnconstrainedLabel {
	unconstrained := make([]UnconstrainedLabel, len(labels))
	for i, label := range labels {
		unconstrained[i] = UnconstrainedLabel{
			Name:         label,
			ExampleValue: "example",
		}
	}
	return unconstrained
}

func promContainsLabel(labels prometheus.ConstrainedLabels, label string) bool {
	for _, l := range labels {
		if l.Name == label {
			return true
		}
	}
	return false
}
