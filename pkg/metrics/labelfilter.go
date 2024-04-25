// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"maps"
)

type LabelFilter map[string]bool

// WithEnabledLabels returns a new LabelFilter with only the labels in enabledLabels enabled.
// If enabledLabels is nil, a copy of the original LabelFilter is returned.
// If enabledLabels is empty, all labels are disabled.
// If enabledLabels contains labels that are not in the original LabelFilter, they are ignored.
func (f LabelFilter) WithEnabledLabels(enabledLabels []string) LabelFilter {
	labelFilter := maps.Clone(f)
	if enabledLabels == nil {
		return labelFilter
	}

	// disable all configurable labels
	for l := range f {
		labelFilter[l] = false
	}

	// enable configured labels
	for _, l := range enabledLabels {
		// quietly ignore unknown labels
		if _, ok := labelFilter[l]; ok {
			labelFilter[l] = true
		}
	}

	return labelFilter
}
