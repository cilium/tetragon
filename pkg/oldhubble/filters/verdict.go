// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
)

func filterByVerdicts(vs []pb.Verdict) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		for _, verdict := range vs {
			if verdict == flow.GetVerdict() {
				return true
			}
		}

		return false
	}
}

// VerdictFilter implements filtering based on forwarding verdict
type VerdictFilter struct{}

// OnBuildFilter builds a forwarding verdict filter
func (v *VerdictFilter) OnBuildFilter(_ context.Context, ff *pb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetVerdict() != nil {
		fs = append(fs, filterByVerdicts(ff.GetVerdict()))
	}

	return fs, nil
}
