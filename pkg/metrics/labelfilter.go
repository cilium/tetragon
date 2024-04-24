// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

type LabelFilter map[string]bool

func (f LabelFilter) WithEnabledLabels(enabledLabels []string) LabelFilter {
	labelFilter := make(LabelFilter)
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
