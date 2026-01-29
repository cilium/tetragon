// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tetragoninfo

import (
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
)

func bpfProbes() []*tetragon.GetInfoResponse_Probe {
	var ret []*tetragon.GetInfoResponse_Probe
	for _, featProbe := range bpf.FeatureProbes {
		ret = append(ret, &tetragon.GetInfoResponse_Probe{
			Name:    featProbe.Name,
			Enabled: wrapperspb.Bool(featProbe.Fn()),
		})
	}
	return ret
}
