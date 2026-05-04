// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package selectors

import slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"

func MatchAllLabelSelector(s *slimv1.LabelSelector) bool {
	all := &slimv1.LabelSelector{}
	return all.DeepEqual(s)
}

func MatchNothingLabelSelector(s *slimv1.LabelSelector) bool {
	return s == nil
}
