// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runner

import (
	"fmt"
	"strconv"
	"strings"
)

type PortForward struct {
	HostPort int
	VMPort   int
	Protocol string
}

type PortForwards []PortForward

func ParsePortForward(flags []string) (PortForwards, error) {
	var forwards []PortForward
	for _, flag := range flags {
		hostPortStr, vmPortAndProto, found := strings.Cut(flag, ":")
		if !found {
			hostPort, err := strconv.Atoi(flag)
			if err != nil {
				return nil, fmt.Errorf("'%s' is not a valid port number", flag)
			}
			forwards = append(forwards, PortForward{
				HostPort: hostPort,
				VMPort:   hostPort,
				Protocol: "tcp",
			})
			continue
		}

		hostPort, err := strconv.Atoi(hostPortStr)
		if err != nil {
			return nil, fmt.Errorf("'%s' is not a valid port number", hostPortStr)
		}

		vmPortStr, proto, found := strings.Cut(vmPortAndProto, ":")
		if !found {
			vmPort, err := strconv.Atoi(vmPortAndProto)
			if err != nil {
				return nil, fmt.Errorf("'%s' is not a valid port number", vmPortAndProto)
			}
			forwards = append(forwards, PortForward{
				HostPort: hostPort,
				VMPort:   vmPort,
				Protocol: "tcp",
			})
			continue
		}

		vmPort, err := strconv.Atoi(vmPortStr)
		if err != nil {
			return nil, fmt.Errorf("'%s' is not a valid port number", vmPortStr)
		}

		proto = strings.ToLower(proto)
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("port forward protocol must be tcp or udp")
		}

		forwards = append(forwards, PortForward{
			HostPort: hostPort,
			VMPort:   vmPort,
			Protocol: proto,
		})
	}

	return forwards, nil
}

func (pf PortForwards) QemuArgs() []string {
	netdev := "user,id=user.0"
	for _, fwd := range pf {
		netdev = fmt.Sprintf("%s,hostfwd=%s::%d-:%d", netdev, fwd.Protocol, fwd.HostPort, fwd.VMPort)
	}
	return []string{
		"-netdev", netdev,
		"-device", "virtio-net-pci,netdev=user.0",
	}
}
