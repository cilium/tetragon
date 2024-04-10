// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"maps"
	"strings"

	"github.com/cilium/tetragon/pkg/metrics/consts"
)

func parseMetricsLabelFilter(enabledLabels string) map[string]bool {
	labelsFilter := maps.Clone(consts.DefaultLabelsFilter)

	// disable all configurable labels
	for l := range labelsFilter {
		labelsFilter[l] = false
	}

	// enable configured labels
	for _, l := range strings.Split(enabledLabels, ",") {
		l = strings.TrimSpace(l)
		// quietly ignore unknown labels
		if _, ok := labelsFilter[l]; ok {
			labelsFilter[l] = true
		}
	}

	return labelsFilter
}
