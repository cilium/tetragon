// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package unloader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
)

// rawDetachUnloader can be used to unload cgroup and sockmap programs.
type RawDetachUnloader struct {
	TargetFD   int
	Name       string
	Prog       *ebpf.Program
	AttachType ebpf.AttachType
}

func (rdu *RawDetachUnloader) Unload(unpin bool) error {
	defer rdu.Prog.Close()
	// PROG_ATTACH does not return any link, so there's nothing to unpin,
	// but we must skip the detach operation for 'unpin == false' otherwise
	// the pinned program will be un-attached
	if unpin {
		err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  rdu.TargetFD,
			Program: rdu.Prog,
			Attach:  rdu.AttachType,
		})
		if err != nil {
			return fmt.Errorf("failed to detach %s: %w", rdu.Name, err)
		}
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

func (tu TcUnloader) Unload(unpin bool) error {
	// PROG_ATTACH does not return any link, so there's nothing to unpin,
	// but we must skip the detach operation for 'unpin == false' otherwise
	// the pinned program will be un-attached
	if unpin {
		for _, att := range tu.Attachments {
			if err := detachTC(att.LinkName, att.IsIngress); err != nil {
				return err
			}
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

// RelinkUnloader is an unloader that allows unlinking/relinking as well.
type RelinkUnloader struct {
	// UnloadProg unloads the program
	UnloadProg func(unpin bool) error
	// IsLinked is true iff the program is linked
	IsLinked bool
	// Link is the link object (valid iff IsLinked)
	Link link.Link
	// Function to relink (requires calling Unlink first)
	RelinkFn func() (link.Link, error)
}

func (u *RelinkUnloader) Unload(unpin bool) error {
	var ret error
	if u.IsLinked {
		if unpin {
			u.Link.Unpin()
		}
		if err := u.Link.Close(); err != nil {
			ret = multierr.Append(ret, err)
		} else {
			u.IsLinked = false
		}
	}
	ret = multierr.Append(ret, u.UnloadProg(unpin))
	return ret
}

func (u *RelinkUnloader) Unlink() error {
	if !u.IsLinked {
		return errors.New("Unlink failed: program not linked")
	}

	if err := u.Link.Close(); err != nil {
		return fmt.Errorf("Unlink failed: %w", err)
	}

	u.IsLinked = false
	return nil
}

func (u *RelinkUnloader) Relink() error {
	if u.IsLinked {
		return errors.New("Relink failed: program already linked")
	}

	link, err := u.RelinkFn()
	if err != nil {
		return fmt.Errorf("Relink failed: %w", err)
	}

	u.Link = link
	u.IsLinked = true
	return nil
}

// MultiRelinkUnloader is an unloader for multiple links that allows unlinking/relinking as well.
type MultiRelinkUnloader struct {
	// UnloadProg unloads the program
	UnloadProg func(unpin bool) error
	// IsLinked is true iff the program is linked
	IsLinked bool
	// Link is the link object (valid iff IsLinked)
	Links []link.Link
	// Function to relink (requires calling Unlink first)
	RelinkFn func() ([]link.Link, error)
}

func (u *MultiRelinkUnloader) Unload(unpin bool) error {
	var ret error
	for _, link := range u.Links {
		if unpin {
			link.Unpin()
		}
		if err := link.Close(); err != nil {
			ret = multierr.Append(ret, err)
		}
	}
	ret = multierr.Append(ret, u.UnloadProg(unpin))
	return ret
}

func (u *MultiRelinkUnloader) Unlink() error {
	var ret error
	if !u.IsLinked {
		return errors.New("Unlink failed: program not linked")
	}
	for _, link := range u.Links {
		if err := link.Close(); err != nil {
			ret = multierr.Append(ret, err)
		}
	}
	u.IsLinked = false
	return nil
}

func (u *MultiRelinkUnloader) Relink() error {
	if u.IsLinked {
		return errors.New("Relink failed: program already linked")
	}

	links, err := u.RelinkFn()
	if err != nil {
		return fmt.Errorf("Relink failed: %w", err)
	}

	u.Links = links
	u.IsLinked = true
	return nil
}
