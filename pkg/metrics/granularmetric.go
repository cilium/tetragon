// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

type initLabelValuesFunc func(...string)

// initAllCombinations initializes a metric with all possible combinations of
// label values.
func initAllCombinations(initMetric initLabelValuesFunc, labels []ConstrainedLabel) {
	initCombinations(initMetric, labels, make([]string, len(labels)), 0)
}

// initCombinations is a helper function that recursively initializes a metric
// with possible combinations of label values.
//
// There are a few assumptions about the arguments:
// - initMetric is not nil
// - labels and lvs have the same length
// - cursor is in the range [0, len(labels)]
//
// If any of these is not met, the function will do nothing.
func initCombinations(initMetric initLabelValuesFunc, labels []ConstrainedLabel, lvs []string, cursor int) {
	if initMetric == nil || len(labels) != len(lvs) || cursor < 0 || cursor > len(labels) {
		// The function was called with invalid arguments. Silently return.
		return
	}
	if cursor == len(labels) {
		initMetric(lvs...)
		return
	}
	for _, val := range labels[cursor].Values {
		lvs[cursor] = val
		initCombinations(initMetric, labels, lvs, cursor+1)
	}
}

// initForDocs initializes the metric for the purpose of generating
// documentation. For each of FilteredLabels and unconstrained labels, it sets
// an example value and initializes the metric with it. For each of constrained
// labels - iterates over all values and initializes the metric with each of
// them. The metrics initialized would likely be considered invalid in a real
// metrics server - but here we care only about extracting labels for
// documentation, so we don't try to make the metrics realistic.
func initForDocs[L FilteredLabels](
	initMetric initLabelValuesFunc, constrained []ConstrainedLabel, unconstrained []UnconstrainedLabel,
) {
	var dummy L
	commonLabels := dummy.Keys()
	lvs := make([]string, len(commonLabels)+len(constrained)+len(unconstrained))

	// first FilteredLabels
	current := lvs
	if ex, ok := any(dummy).(FilteredLabelsExample); ok {
		for i, val := range ex.Example().Values() {
			current[i] = val
			initMetric(lvs...)
		}
	} else {
		for i := range commonLabels {
			current[i] = "example"
			initMetric(lvs...)
		}
	}
	// second constrained labels
	current = current[len(commonLabels):]
	for i := range constrained {
		for _, val := range constrained[i].Values {
			current[i] = val
			initMetric(lvs...)
		}
	}
	// third unconstrained labels
	current = current[len(constrained):]
	for i := range unconstrained {
		current[i] = unconstrained[i].ExampleValue
		initMetric(lvs...)
	}
}
