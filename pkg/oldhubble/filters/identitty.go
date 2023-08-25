// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
)

func sourceEndpoint(ev *v1.Event) *pb.Endpoint {
	return ev.GetFlow().GetSource()
}

func destinationEndpoint(ev *v1.Event) *pb.Endpoint {
	return ev.GetFlow().GetDestination()
}

func filterByIdentity(identities []uint32, getEndpoint func(*v1.Event) *pb.Endpoint) FilterFunc {
	return func(ev *v1.Event) bool {
		if endpoint := getEndpoint(ev); endpoint != nil {
			for _, i := range identities {
				if i == endpoint.Identity {
					return true
				}
			}
		}
		return false
	}
}

// IdentityFilter implements filtering based on security identity
type IdentityFilter struct{}

// OnBuildFilter builds a security identity filter
func (i *IdentityFilter) OnBuildFilter(_ context.Context, ff *pb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourceIdentity() != nil {
		fs = append(fs, filterByIdentity(ff.GetSourceIdentity(), sourceEndpoint))
	}

	if ff.GetDestinationIdentity() != nil {
		fs = append(fs, filterByIdentity(ff.GetDestinationIdentity(), destinationEndpoint))
	}

	return fs, nil
}
