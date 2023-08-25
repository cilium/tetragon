// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"google.golang.org/protobuf/types/known/timestamppb"

	//nolint:staticcheck // SA1004 ignore this!
	"github.com/golang/protobuf/proto"
)

// Flow is an interface matching pb.Flow
type Flow interface {
	proto.Message
	GetTime() *timestamppb.Timestamp
	GetVerdict() pb.Verdict
	GetDropReason() uint32
	GetEthernet() *pb.Ethernet
	GetIP() *pb.IP
	GetL4() *pb.Layer4
	GetSource() *pb.Endpoint
	GetDestination() *pb.Endpoint
	GetType() pb.FlowType
	GetNodeName() string
	GetSourceNames() []string
	GetDestinationNames() []string
	GetL7() *pb.Layer7
	GetReply() bool
	GetEventType() *pb.CiliumEventType
	GetSourceService() *pb.Service
	GetDestinationService() *pb.Service
	GetSummary() string
}

// This ensures that the protobuf definition implements the interface
var _ Flow = &pb.Flow{}

// EndpointInfo defines readable fields of a Cilium endpoint.
type EndpointInfo interface {
	GetID() uint64
	GetIdentity() identity.NumericIdentity
	GetK8sPodName() string
	GetK8sNamespace() string
	GetLabels() []string
}
