// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package unloader

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Unloader describes how to unload a sensor resource, e.g.
// programs or maps.
type Unloader interface {
	Unload() error
}

// chainUnloader is an unloader for multiple resources.
// Useful when a loading operation needs to be unwinded due to an error.
type ChainUnloader []Unloader

type chainUnloaderErrors struct {
	errors []error
}

func (cue chainUnloaderErrors) Error() string {
	strs := []string{}
	for _, e := range cue.errors {
		strs = append(strs, e.Error())
	}
	return strings.Join(strs, "; ")
}

func (cu ChainUnloader) Unload() error {
	var cue chainUnloaderErrors
	for i := len(cu) - 1; i >= 0; i-- {
		if err := (cu)[i].Unload(); err != nil {
			cue.errors = append(cue.errors, err)
		}
	}
	if len(cue.errors) > 0 {
		return cue
	}
	return nil
}

// PinUnloader unpins and closes a BPF program.
type PinUnloader struct {
	Prog *ebpf.Program
}

func (pu PinUnloader) Unload() error {
	defer pu.Prog.Close()
	return pu.Prog.Unpin()
}

// PinUnloader unpins and closes a BPF program.
type LinkUnloader struct {
	Link link.Link
}

func (lu LinkUnloader) Unload() error {
	return lu.Link.Close()
}

// rawDetachUnloader can be used to unload cgroup and sockmap programs.
type RawDetachUnloader struct {
	TargetFD   int
	Name       string
	Prog       *ebpf.Program
	AttachType ebpf.AttachType
}

func (rdu *RawDetachUnloader) Unload() error {
	defer rdu.Prog.Close()
	err := link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  rdu.TargetFD,
		Program: rdu.Prog,
		Attach:  rdu.AttachType,
	})
	if err != nil {
		return fmt.Errorf("failed to detach %s: %w", rdu.Name, err)
	}
	return nil
}

// TcUnloader unloads programs attached to TC filters
type TcUnloader struct {
	Attachments []TcAttachment
}

type TcAttachment struct {
	LinkName  string
	IsIngress bool
}

func (tu TcUnloader) Unload() error {
	for _, att := range tu.Attachments {
		if err := detachTC(att.LinkName, att.IsIngress); err != nil {
			return err
		}
	}
	return nil
}

func detachTC(linkName string, ingress bool) error {
	var parent uint32
	var name string

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %w", linkName, err)
	}

	if ingress {
		parent = netlink.HANDLE_MIN_INGRESS
		name = "fgs-ingress"
	} else {
		parent = netlink.HANDLE_MIN_EGRESS
		name = "fgs-egress"
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    parent,
		Handle:    netlink.MakeHandle(0, 2),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Name:         name,
		DirectAction: true,
	}
	if filter.Fd < 0 {
		return fmt.Errorf("BpfFilter failed (%s): %d", linkName, filter.Fd)
	}
	if err = netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("FilterDel failed (%s): %w", linkName, err)
	}
	return err

}
