// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package unloader

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
)

// Unloader describes how to unload a sensor resource, e.g.
// programs or maps.
type Unloader interface {
	Unload(unpin bool) error
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

func (cu ChainUnloader) Unload(unpin bool) error {
	var cue chainUnloaderErrors
	for i := len(cu) - 1; i >= 0; i-- {
		if err := (cu)[i].Unload(unpin); err != nil {
			cue.errors = append(cue.errors, err)
		}
	}
	if len(cue.errors) > 0 {
		return cue
	}
	return nil
}

// ProgUnloader unpins and closes a BPF program.
type ProgUnloader struct {
	Prog *ebpf.Program
}

func (pu ProgUnloader) Unload(unpin bool) error {
	if unpin {
		pu.Prog.Unpin()
	}
	return pu.Prog.Close()
}

// ProgUnloader unpins and closes a BPF program.
type LinkUnloader struct {
	Link link.Link
}

func (lu LinkUnloader) Unload(unpin bool) error {
	if unpin {
		lu.Link.Unpin()
	}
	return lu.Link.Close()
}

// rawDetachUnloader can be used to unload cgroup and sockmap programs.
type RawDetachUnloader struct {
	TargetFD   int
	Name       string
	Prog       *ebpf.Program
	AttachType ebpf.AttachType
}

func (rdu *RawDetachUnloader) Unload(_ bool) error {
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

func (tu TcUnloader) Unload(_ bool) error {
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
