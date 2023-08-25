// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
)

func filterByReplyField(replyParams []bool) FilterFunc {
	return func(ev *v1.Event) bool {
		if len(replyParams) == 0 {
			return true
		}
		switch ev.Event.(type) {
		case v1.Flow:
			reply := ev.GetFlow().GetReply()
			for _, replyParam := range replyParams {
				if reply == replyParam {
					return true
				}
			}
		}
		return false
	}
}

// ReplyFilter implements filtering for reply flows
type ReplyFilter struct{}

// OnBuildFilter builds a reply filter
func (r *ReplyFilter) OnBuildFilter(_ context.Context, ff *pb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetReply() != nil {
		fs = append(fs, filterByReplyField(ff.GetReply()))
	}

	return fs, nil
}
