//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepequal-gen. DO NOT EDIT.

package v2alpha1

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Advertisement) DeepEqual(other *Advertisement) bool {
	if other == nil {
		return false
	}

	if in.AdvertisementType != other.AdvertisementType {
		return false
	}
	if (in.Selector == nil) != (other.Selector == nil) {
		return false
	} else if in.Selector != nil {
		if !in.Selector.DeepEqual(other.Selector) {
			return false
		}
	}

	if (in.Attributes == nil) != (other.Attributes == nil) {
		return false
	} else if in.Attributes != nil {
		if !in.Attributes.DeepEqual(other.Attributes) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *BGPCommunities) DeepEqual(other *BGPCommunities) bool {
	if other == nil {
		return false
	}

	if ((in.Standard != nil) && (other.Standard != nil)) || ((in.Standard == nil) != (other.Standard == nil)) {
		in, other := &in.Standard, &other.Standard
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if ((in.Large != nil) && (other.Large != nil)) || ((in.Large == nil) != (other.Large == nil)) {
		in, other := &in.Large, &other.Large
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPAdvertisement) DeepEqual(other *CiliumBGPAdvertisement) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPAdvertisementSpec) DeepEqual(other *CiliumBGPAdvertisementSpec) bool {
	if other == nil {
		return false
	}

	if ((in.Advertisements != nil) && (other.Advertisements != nil)) || ((in.Advertisements == nil) != (other.Advertisements == nil)) {
		in, other := &in.Advertisements, &other.Advertisements
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPAttributes) DeepEqual(other *CiliumBGPAttributes) bool {
	if other == nil {
		return false
	}

	if (in.Community == nil) != (other.Community == nil) {
		return false
	} else if in.Community != nil {
		if !in.Community.DeepEqual(other.Community) {
			return false
		}
	}

	if (in.LocalPreference == nil) != (other.LocalPreference == nil) {
		return false
	} else if in.LocalPreference != nil {
		if *in.LocalPreference != *other.LocalPreference {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPClusterConfig) DeepEqual(other *CiliumBGPClusterConfig) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPClusterConfigSpec) DeepEqual(other *CiliumBGPClusterConfigSpec) bool {
	if other == nil {
		return false
	}

	if (in.NodeSelector == nil) != (other.NodeSelector == nil) {
		return false
	} else if in.NodeSelector != nil {
		if !in.NodeSelector.DeepEqual(other.NodeSelector) {
			return false
		}
	}

	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPFamily) DeepEqual(other *CiliumBGPFamily) bool {
	if other == nil {
		return false
	}

	if in.Afi != other.Afi {
		return false
	}
	if in.Safi != other.Safi {
		return false
	}
	if (in.Advertisements == nil) != (other.Advertisements == nil) {
		return false
	} else if in.Advertisements != nil {
		if !in.Advertisements.DeepEqual(other.Advertisements) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPInstance) DeepEqual(other *CiliumBGPInstance) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.LocalASN == nil) != (other.LocalASN == nil) {
		return false
	} else if in.LocalASN != nil {
		if *in.LocalASN != *other.LocalASN {
			return false
		}
	}

	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNeighbor) DeepEqual(other *CiliumBGPNeighbor) bool {
	if other == nil {
		return false
	}

	if in.PeerAddress != other.PeerAddress {
		return false
	}
	if (in.PeerPort == nil) != (other.PeerPort == nil) {
		return false
	} else if in.PeerPort != nil {
		if *in.PeerPort != *other.PeerPort {
			return false
		}
	}

	if in.PeerASN != other.PeerASN {
		return false
	}
	if (in.AuthSecretRef == nil) != (other.AuthSecretRef == nil) {
		return false
	} else if in.AuthSecretRef != nil {
		if *in.AuthSecretRef != *other.AuthSecretRef {
			return false
		}
	}

	if (in.EBGPMultihopTTL == nil) != (other.EBGPMultihopTTL == nil) {
		return false
	} else if in.EBGPMultihopTTL != nil {
		if *in.EBGPMultihopTTL != *other.EBGPMultihopTTL {
			return false
		}
	}

	if (in.ConnectRetryTimeSeconds == nil) != (other.ConnectRetryTimeSeconds == nil) {
		return false
	} else if in.ConnectRetryTimeSeconds != nil {
		if *in.ConnectRetryTimeSeconds != *other.ConnectRetryTimeSeconds {
			return false
		}
	}

	if (in.HoldTimeSeconds == nil) != (other.HoldTimeSeconds == nil) {
		return false
	} else if in.HoldTimeSeconds != nil {
		if *in.HoldTimeSeconds != *other.HoldTimeSeconds {
			return false
		}
	}

	if (in.KeepAliveTimeSeconds == nil) != (other.KeepAliveTimeSeconds == nil) {
		return false
	} else if in.KeepAliveTimeSeconds != nil {
		if *in.KeepAliveTimeSeconds != *other.KeepAliveTimeSeconds {
			return false
		}
	}

	if (in.GracefulRestart == nil) != (other.GracefulRestart == nil) {
		return false
	} else if in.GracefulRestart != nil {
		if !in.GracefulRestart.DeepEqual(other.GracefulRestart) {
			return false
		}
	}

	if ((in.Families != nil) && (other.Families != nil)) || ((in.Families == nil) != (other.Families == nil)) {
		in, other := &in.Families, &other.Families
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	if ((in.AdvertisedPathAttributes != nil) && (other.AdvertisedPathAttributes != nil)) || ((in.AdvertisedPathAttributes == nil) != (other.AdvertisedPathAttributes == nil)) {
		in, other := &in.AdvertisedPathAttributes, &other.AdvertisedPathAttributes
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNeighborGracefulRestart) DeepEqual(other *CiliumBGPNeighborGracefulRestart) bool {
	if other == nil {
		return false
	}

	if in.Enabled != other.Enabled {
		return false
	}
	if (in.RestartTimeSeconds == nil) != (other.RestartTimeSeconds == nil) {
		return false
	} else if in.RestartTimeSeconds != nil {
		if *in.RestartTimeSeconds != *other.RestartTimeSeconds {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeConfig) DeepEqual(other *CiliumBGPNodeConfig) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	if !in.Status.DeepEqual(&other.Status) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeConfigInstanceOverride) DeepEqual(other *CiliumBGPNodeConfigInstanceOverride) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.RouterID == nil) != (other.RouterID == nil) {
		return false
	} else if in.RouterID != nil {
		if *in.RouterID != *other.RouterID {
			return false
		}
	}

	if (in.LocalPort == nil) != (other.LocalPort == nil) {
		return false
	} else if in.LocalPort != nil {
		if *in.LocalPort != *other.LocalPort {
			return false
		}
	}

	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeConfigOverride) DeepEqual(other *CiliumBGPNodeConfigOverride) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeConfigOverrideSpec) DeepEqual(other *CiliumBGPNodeConfigOverrideSpec) bool {
	if other == nil {
		return false
	}

	if in.NodeRef != other.NodeRef {
		return false
	}
	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeConfigPeerOverride) DeepEqual(other *CiliumBGPNodeConfigPeerOverride) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.LocalAddress == nil) != (other.LocalAddress == nil) {
		return false
	} else if in.LocalAddress != nil {
		if *in.LocalAddress != *other.LocalAddress {
			return false
		}
	}

	if (in.LocalPort == nil) != (other.LocalPort == nil) {
		return false
	} else if in.LocalPort != nil {
		if *in.LocalPort != *other.LocalPort {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeInstance) DeepEqual(other *CiliumBGPNodeInstance) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.LocalASN == nil) != (other.LocalASN == nil) {
		return false
	} else if in.LocalASN != nil {
		if *in.LocalASN != *other.LocalASN {
			return false
		}
	}

	if (in.RouterID == nil) != (other.RouterID == nil) {
		return false
	} else if in.RouterID != nil {
		if *in.RouterID != *other.RouterID {
			return false
		}
	}

	if (in.LocalPort == nil) != (other.LocalPort == nil) {
		return false
	} else if in.LocalPort != nil {
		if *in.LocalPort != *other.LocalPort {
			return false
		}
	}

	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeInstanceStatus) DeepEqual(other *CiliumBGPNodeInstanceStatus) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.LocalASN == nil) != (other.LocalASN == nil) {
		return false
	} else if in.LocalASN != nil {
		if *in.LocalASN != *other.LocalASN {
			return false
		}
	}

	if ((in.PeerStatuses != nil) && (other.PeerStatuses != nil)) || ((in.PeerStatuses == nil) != (other.PeerStatuses == nil)) {
		in, other := &in.PeerStatuses, &other.PeerStatuses
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodePeer) DeepEqual(other *CiliumBGPNodePeer) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.PeerAddress == nil) != (other.PeerAddress == nil) {
		return false
	} else if in.PeerAddress != nil {
		if *in.PeerAddress != *other.PeerAddress {
			return false
		}
	}

	if (in.PeerASN == nil) != (other.PeerASN == nil) {
		return false
	} else if in.PeerASN != nil {
		if *in.PeerASN != *other.PeerASN {
			return false
		}
	}

	if (in.LocalAddress == nil) != (other.LocalAddress == nil) {
		return false
	} else if in.LocalAddress != nil {
		if *in.LocalAddress != *other.LocalAddress {
			return false
		}
	}

	if (in.PeerConfigRef == nil) != (other.PeerConfigRef == nil) {
		return false
	} else if in.PeerConfigRef != nil {
		if !in.PeerConfigRef.DeepEqual(other.PeerConfigRef) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodePeerStatus) DeepEqual(other *CiliumBGPNodePeerStatus) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if in.PeerAddress != other.PeerAddress {
		return false
	}
	if (in.PeerASN == nil) != (other.PeerASN == nil) {
		return false
	} else if in.PeerASN != nil {
		if *in.PeerASN != *other.PeerASN {
			return false
		}
	}

	if (in.PeeringState == nil) != (other.PeeringState == nil) {
		return false
	} else if in.PeeringState != nil {
		if *in.PeeringState != *other.PeeringState {
			return false
		}
	}

	if (in.Timers == nil) != (other.Timers == nil) {
		return false
	} else if in.Timers != nil {
		if !in.Timers.DeepEqual(other.Timers) {
			return false
		}
	}

	if (in.Uptime == nil) != (other.Uptime == nil) {
		return false
	} else if in.Uptime != nil {
		if *in.Uptime != *other.Uptime {
			return false
		}
	}

	if (in.RoutesReceived == nil) != (other.RoutesReceived == nil) {
		return false
	} else if in.RoutesReceived != nil {
		if *in.RoutesReceived != *other.RoutesReceived {
			return false
		}
	}

	if (in.RoutesAdvertised == nil) != (other.RoutesAdvertised == nil) {
		return false
	} else if in.RoutesAdvertised != nil {
		if *in.RoutesAdvertised != *other.RoutesAdvertised {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeSpec) DeepEqual(other *CiliumBGPNodeSpec) bool {
	if other == nil {
		return false
	}

	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNodeStatus) DeepEqual(other *CiliumBGPNodeStatus) bool {
	if other == nil {
		return false
	}

	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPathAttributes) DeepEqual(other *CiliumBGPPathAttributes) bool {
	if other == nil {
		return false
	}

	if in.SelectorType != other.SelectorType {
		return false
	}
	if (in.Selector == nil) != (other.Selector == nil) {
		return false
	} else if in.Selector != nil {
		if !in.Selector.DeepEqual(other.Selector) {
			return false
		}
	}

	if (in.Communities == nil) != (other.Communities == nil) {
		return false
	} else if in.Communities != nil {
		if !in.Communities.DeepEqual(other.Communities) {
			return false
		}
	}

	if (in.LocalPreference == nil) != (other.LocalPreference == nil) {
		return false
	} else if in.LocalPreference != nil {
		if *in.LocalPreference != *other.LocalPreference {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPeer) DeepEqual(other *CiliumBGPPeer) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.PeerAddress == nil) != (other.PeerAddress == nil) {
		return false
	} else if in.PeerAddress != nil {
		if *in.PeerAddress != *other.PeerAddress {
			return false
		}
	}

	if (in.PeerASN == nil) != (other.PeerASN == nil) {
		return false
	} else if in.PeerASN != nil {
		if *in.PeerASN != *other.PeerASN {
			return false
		}
	}

	if (in.PeerConfigRef == nil) != (other.PeerConfigRef == nil) {
		return false
	} else if in.PeerConfigRef != nil {
		if !in.PeerConfigRef.DeepEqual(other.PeerConfigRef) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPeerConfig) DeepEqual(other *CiliumBGPPeerConfig) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPeerConfigSpec) DeepEqual(other *CiliumBGPPeerConfigSpec) bool {
	if other == nil {
		return false
	}

	if (in.Transport == nil) != (other.Transport == nil) {
		return false
	} else if in.Transport != nil {
		if !in.Transport.DeepEqual(other.Transport) {
			return false
		}
	}

	if (in.Timers == nil) != (other.Timers == nil) {
		return false
	} else if in.Timers != nil {
		if !in.Timers.DeepEqual(other.Timers) {
			return false
		}
	}

	if (in.AuthSecretRef == nil) != (other.AuthSecretRef == nil) {
		return false
	} else if in.AuthSecretRef != nil {
		if *in.AuthSecretRef != *other.AuthSecretRef {
			return false
		}
	}

	if (in.GracefulRestart == nil) != (other.GracefulRestart == nil) {
		return false
	} else if in.GracefulRestart != nil {
		if !in.GracefulRestart.DeepEqual(other.GracefulRestart) {
			return false
		}
	}

	if (in.EBGPMultihop == nil) != (other.EBGPMultihop == nil) {
		return false
	} else if in.EBGPMultihop != nil {
		if *in.EBGPMultihop != *other.EBGPMultihop {
			return false
		}
	}

	if ((in.Families != nil) && (other.Families != nil)) || ((in.Families == nil) != (other.Families == nil)) {
		in, other := &in.Families, &other.Families
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPeeringPolicy) DeepEqual(other *CiliumBGPPeeringPolicy) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPeeringPolicySpec) DeepEqual(other *CiliumBGPPeeringPolicySpec) bool {
	if other == nil {
		return false
	}

	if (in.NodeSelector == nil) != (other.NodeSelector == nil) {
		return false
	} else if in.NodeSelector != nil {
		if !in.NodeSelector.DeepEqual(other.NodeSelector) {
			return false
		}
	}

	if ((in.VirtualRouters != nil) && (other.VirtualRouters != nil)) || ((in.VirtualRouters == nil) != (other.VirtualRouters == nil)) {
		in, other := &in.VirtualRouters, &other.VirtualRouters
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPTimers) DeepEqual(other *CiliumBGPTimers) bool {
	if other == nil {
		return false
	}

	if (in.ConnectRetryTimeSeconds == nil) != (other.ConnectRetryTimeSeconds == nil) {
		return false
	} else if in.ConnectRetryTimeSeconds != nil {
		if *in.ConnectRetryTimeSeconds != *other.ConnectRetryTimeSeconds {
			return false
		}
	}

	if (in.HoldTimeSeconds == nil) != (other.HoldTimeSeconds == nil) {
		return false
	} else if in.HoldTimeSeconds != nil {
		if *in.HoldTimeSeconds != *other.HoldTimeSeconds {
			return false
		}
	}

	if (in.KeepAliveTimeSeconds == nil) != (other.KeepAliveTimeSeconds == nil) {
		return false
	} else if in.KeepAliveTimeSeconds != nil {
		if *in.KeepAliveTimeSeconds != *other.KeepAliveTimeSeconds {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPTimersState) DeepEqual(other *CiliumBGPTimersState) bool {
	if other == nil {
		return false
	}

	if (in.AppliedHoldTimeSeconds == nil) != (other.AppliedHoldTimeSeconds == nil) {
		return false
	} else if in.AppliedHoldTimeSeconds != nil {
		if *in.AppliedHoldTimeSeconds != *other.AppliedHoldTimeSeconds {
			return false
		}
	}

	if (in.AppliedKeepaliveSeconds == nil) != (other.AppliedKeepaliveSeconds == nil) {
		return false
	} else if in.AppliedKeepaliveSeconds != nil {
		if *in.AppliedKeepaliveSeconds != *other.AppliedKeepaliveSeconds {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPTransport) DeepEqual(other *CiliumBGPTransport) bool {
	if other == nil {
		return false
	}

	if (in.LocalPort == nil) != (other.LocalPort == nil) {
		return false
	} else if in.LocalPort != nil {
		if *in.LocalPort != *other.LocalPort {
			return false
		}
	}

	if (in.PeerPort == nil) != (other.PeerPort == nil) {
		return false
	} else if in.PeerPort != nil {
		if *in.PeerPort != *other.PeerPort {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPVirtualRouter) DeepEqual(other *CiliumBGPVirtualRouter) bool {
	if other == nil {
		return false
	}

	if in.LocalASN != other.LocalASN {
		return false
	}
	if (in.ExportPodCIDR == nil) != (other.ExportPodCIDR == nil) {
		return false
	} else if in.ExportPodCIDR != nil {
		if *in.ExportPodCIDR != *other.ExportPodCIDR {
			return false
		}
	}

	if (in.PodIPPoolSelector == nil) != (other.PodIPPoolSelector == nil) {
		return false
	} else if in.PodIPPoolSelector != nil {
		if !in.PodIPPoolSelector.DeepEqual(other.PodIPPoolSelector) {
			return false
		}
	}

	if (in.ServiceSelector == nil) != (other.ServiceSelector == nil) {
		return false
	} else if in.ServiceSelector != nil {
		if !in.ServiceSelector.DeepEqual(other.ServiceSelector) {
			return false
		}
	}

	if ((in.Neighbors != nil) && (other.Neighbors != nil)) || ((in.Neighbors == nil) != (other.Neighbors == nil)) {
		in, other := &in.Neighbors, &other.Neighbors
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumCIDRGroupSpec) DeepEqual(other *CiliumCIDRGroupSpec) bool {
	if other == nil {
		return false
	}

	if ((in.ExternalCIDRs != nil) && (other.ExternalCIDRs != nil)) || ((in.ExternalCIDRs == nil) != (other.ExternalCIDRs == nil)) {
		in, other := &in.ExternalCIDRs, &other.ExternalCIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumEndpointSlice) DeepEqual(other *CiliumEndpointSlice) bool {
	if other == nil {
		return false
	}

	if in.Namespace != other.Namespace {
		return false
	}
	if ((in.Endpoints != nil) && (other.Endpoints != nil)) || ((in.Endpoints == nil) != (other.Endpoints == nil)) {
		in, other := &in.Endpoints, &other.Endpoints
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumL2AnnouncementPolicy) DeepEqual(other *CiliumL2AnnouncementPolicy) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumL2AnnouncementPolicySpec) DeepEqual(other *CiliumL2AnnouncementPolicySpec) bool {
	if other == nil {
		return false
	}

	if (in.NodeSelector == nil) != (other.NodeSelector == nil) {
		return false
	} else if in.NodeSelector != nil {
		if !in.NodeSelector.DeepEqual(other.NodeSelector) {
			return false
		}
	}

	if (in.ServiceSelector == nil) != (other.ServiceSelector == nil) {
		return false
	} else if in.ServiceSelector != nil {
		if !in.ServiceSelector.DeepEqual(other.ServiceSelector) {
			return false
		}
	}

	if in.LoadBalancerIPs != other.LoadBalancerIPs {
		return false
	}
	if in.ExternalIPs != other.ExternalIPs {
		return false
	}
	if ((in.Interfaces != nil) && (other.Interfaces != nil)) || ((in.Interfaces == nil) != (other.Interfaces == nil)) {
		in, other := &in.Interfaces, &other.Interfaces
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumLoadBalancerIPPool) DeepEqual(other *CiliumLoadBalancerIPPool) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumLoadBalancerIPPoolIPBlock) DeepEqual(other *CiliumLoadBalancerIPPoolIPBlock) bool {
	if other == nil {
		return false
	}

	if in.Cidr != other.Cidr {
		return false
	}
	if in.Start != other.Start {
		return false
	}
	if in.Stop != other.Stop {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumLoadBalancerIPPoolSpec) DeepEqual(other *CiliumLoadBalancerIPPoolSpec) bool {
	if other == nil {
		return false
	}

	if (in.ServiceSelector == nil) != (other.ServiceSelector == nil) {
		return false
	} else if in.ServiceSelector != nil {
		if !in.ServiceSelector.DeepEqual(other.ServiceSelector) {
			return false
		}
	}

	if in.AllowFirstLastIPs != other.AllowFirstLastIPs {
		return false
	}
	if ((in.Cidrs != nil) && (other.Cidrs != nil)) || ((in.Cidrs == nil) != (other.Cidrs == nil)) {
		in, other := &in.Cidrs, &other.Cidrs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	if ((in.Blocks != nil) && (other.Blocks != nil)) || ((in.Blocks == nil) != (other.Blocks == nil)) {
		in, other := &in.Blocks, &other.Blocks
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	if in.Disabled != other.Disabled {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumPodIPPool) DeepEqual(other *CiliumPodIPPool) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CoreCiliumEndpoint) DeepEqual(other *CoreCiliumEndpoint) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if in.IdentityID != other.IdentityID {
		return false
	}
	if (in.Networking == nil) != (other.Networking == nil) {
		return false
	} else if in.Networking != nil {
		if !in.Networking.DeepEqual(other.Networking) {
			return false
		}
	}

	if in.Encryption != other.Encryption {
		return false
	}

	if ((in.NamedPorts != nil) && (other.NamedPorts != nil)) || ((in.NamedPorts == nil) != (other.NamedPorts == nil)) {
		in, other := &in.NamedPorts, &other.NamedPorts
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *EgressRule) DeepEqual(other *EgressRule) bool {
	if other == nil {
		return false
	}

	if (in.NamespaceSelector == nil) != (other.NamespaceSelector == nil) {
		return false
	} else if in.NamespaceSelector != nil {
		if !in.NamespaceSelector.DeepEqual(other.NamespaceSelector) {
			return false
		}
	}

	if (in.PodSelector == nil) != (other.PodSelector == nil) {
		return false
	} else if in.PodSelector != nil {
		if !in.PodSelector.DeepEqual(other.PodSelector) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPPoolSpec) DeepEqual(other *IPPoolSpec) bool {
	if other == nil {
		return false
	}

	if (in.IPv4 == nil) != (other.IPv4 == nil) {
		return false
	} else if in.IPv4 != nil {
		if !in.IPv4.DeepEqual(other.IPv4) {
			return false
		}
	}

	if (in.IPv6 == nil) != (other.IPv6 == nil) {
		return false
	} else if in.IPv6 != nil {
		if !in.IPv6.DeepEqual(other.IPv6) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPv4PoolSpec) DeepEqual(other *IPv4PoolSpec) bool {
	if other == nil {
		return false
	}

	if ((in.CIDRs != nil) && (other.CIDRs != nil)) || ((in.CIDRs == nil) != (other.CIDRs == nil)) {
		in, other := &in.CIDRs, &other.CIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if in.MaskSize != other.MaskSize {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPv6PoolSpec) DeepEqual(other *IPv6PoolSpec) bool {
	if other == nil {
		return false
	}

	if ((in.CIDRs != nil) && (other.CIDRs != nil)) || ((in.CIDRs == nil) != (other.CIDRs == nil)) {
		in, other := &in.CIDRs, &other.CIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if in.MaskSize != other.MaskSize {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PeerConfigReference) DeepEqual(other *PeerConfigReference) bool {
	if other == nil {
		return false
	}

	if in.Group != other.Group {
		return false
	}
	if in.Kind != other.Kind {
		return false
	}
	if in.Name != other.Name {
		return false
	}

	return true
}
