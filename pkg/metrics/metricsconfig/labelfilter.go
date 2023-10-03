// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import "strings"

func ParseMetricsLabelFilter(labels string) map[string]interface{} {
	result := make(map[string]interface{})
	for _, label := range strings.Split(labels, ",") {
		result[label] = nil
	}
	return result
}
