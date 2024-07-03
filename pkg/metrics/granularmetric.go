// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"fmt"
	"slices"
)

func validateExtraLabels(common []string, extra []string) error {
	for _, label := range extra {
		if slices.Contains(common, label) {
			return fmt.Errorf("extra labels can't contain any of the following: %v", common)
		}
	}
	return nil
}
