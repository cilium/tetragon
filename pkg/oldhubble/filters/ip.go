// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"net"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
)

func sourceIP(ev *v1.Event) string {
	return ev.GetFlow().GetIP().GetSource()
}

func destinationIP(ev *v1.Event) string {
	return ev.GetFlow().GetIP().GetDestination()
}

func filterByIPs(ips []string, getIP func(*v1.Event) string) (FilterFunc, error) {
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP address in filter: %q", ip)
		}
	}

	return func(ev *v1.Event) bool {
		eventIP := getIP(ev)
		if eventIP == "" {
			return false
		}

		for _, ip := range ips {
			if ip == eventIP {
				return true
			}
		}

		return false
	}, nil
}

// IPFilter implements IP addressing filtering for the source and destination
// address
type IPFilter struct{}

// OnBuildFilter builds an IP address filter
func (f *IPFilter) OnBuildFilter(_ context.Context, ff *pb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourceIp() != nil {
		ipf, err := filterByIPs(ff.GetSourceIp(), sourceIP)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ipf)
	}

	if ff.GetDestinationIp() != nil {
		ipf, err := filterByIPs(ff.GetDestinationIp(), destinationIP)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ipf)
	}

	return fs, nil
}
