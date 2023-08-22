// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/kernels"
	"github.com/cilium/little-vm-helper/pkg/step"
)

// ActionOp is the interface that actions operations need to implement.
//
// Note:
// If you create an instance of ActionOp, you need to add it to
// actionOpInstances so that JSON marshaling/unmarshaling works. Please also
// consider adding a test case in actions_json_test.go to ensure that all
// works.
type ActionOp interface {
	ActionOpName() string
	ToSteps(s *StepConf) ([]step.Step, error)
}

type Action struct {
	Comment string
	Op      ActionOp
}

var actionOpInstances = []ActionOp{
	&RunCommand{},
	&CopyInCommand{},
	&SetHostnameCommand{},
	&MkdirCommand{},
	&UploadCommand{},
	&ChmodCommand{},
	&AppendLineCommand{},
	&LinkCommand{},
	&InstallKernelCommand{},
}

type VirtCustomizeAction struct {
	OpName  string
	getArgs func() []string
}

// RunCommand runs a script in a path specified by a string
type RunCommand struct {
	Cmd string
}

func (rc *RunCommand) ActionOpName() string {
	return "run-command"
}

func (rc *RunCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--run-command", rc.Cmd},
	}}, nil
}

// CopyInCommand copies local files in the image (recursively)
type CopyInCommand struct {
	LocalPath string
	RemoteDir string
}

func (c *CopyInCommand) ActionOpName() string {
	return "copy-in"
}

func (c *CopyInCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--copy-in", fmt.Sprintf("%s:%s", c.LocalPath, c.RemoteDir)},
	}}, nil
}

// SetHostnameCommand sets the hostname
type SetHostnameCommand struct {
	Hostname string
}

func (c *SetHostnameCommand) ActionOpName() string {
	return "set-hostname"
}

func (c *SetHostnameCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--hostname", c.Hostname},
	}}, nil
}

// MkdirCommand creates a directory
type MkdirCommand struct {
	Dir string
}

func (c *MkdirCommand) ActionOpName() string {
	return "mkdir"
}

func (c *MkdirCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--mkdir", c.Dir},
	}}, nil
}

// UploadCommand copies a file to the vim
type UploadCommand struct {
	File string
	Dest string
}

func (c *UploadCommand) ActionOpName() string {
	return "upload"
}

func (c *UploadCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--upload", fmt.Sprintf("%s:%s", c.File, c.Dest)},
	}}, nil
}

// ChmodCommand
type ChmodCommand struct {
	Permissions string
	File        string
}

func (c *ChmodCommand) ActionOpName() string {
	return "chmod"
}

func (c *ChmodCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--chmod", fmt.Sprintf("%s:%s", c.Permissions, c.File)},
	}}, nil
}

// AppendLineCommand
type AppendLineCommand struct {
	File string
	Line string
}

func (c *AppendLineCommand) ActionOpName() string {
	return "append-line"
}

func (c *AppendLineCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--append-line", fmt.Sprintf("%s:%s", c.File, c.Line)},
	}}, nil
}

// LinkCommand
type LinkCommand struct {
	Target string
	Link   string
}

func (c *LinkCommand) ActionOpName() string {
	return "link"
}

func (c *LinkCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	return []step.Step{&VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--link", fmt.Sprintf("%s:%s", c.Target, c.Link)},
	}}, nil
}

// InstallKernelCommand
type InstallKernelCommand struct {
	KernelInstallDir string
}

func (c *InstallKernelCommand) ActionOpName() string {
	return "install-kernel"
}

func (c *InstallKernelCommand) ToSteps(s *StepConf) ([]step.Step, error) {
	installDir := c.KernelInstallDir
	// NB(kkourt): quick hack for having a proper (independent of base
	// directory) relative path for install dirs. Should figure out
	// something cleaner.
	if !filepath.IsAbs(installDir) {
		d, err := filepath.Abs(filepath.Join(s.imagesDir, "..", c.KernelInstallDir))
		if err == nil {
			installDir = d
		}
	}
	kernel, err := kernels.FindKernel(installDir)
	if err != nil {
		return nil, err
	}
	kernelPath := filepath.Join("/", kernel)
	return []step.Step{
		// boot files, configs, etc.
		&VirtCustomizeStep{StepConf: s, Args: []string{"--copy-in", fmt.Sprintf("%s/boot:/", installDir)}},
		// modules
		&VirtCustomizeStep{StepConf: s, Args: []string{"--copy-in", fmt.Sprintf("%s/lib/modules:/lib/", installDir)}},
		&VirtCustomizeStep{StepConf: s, Args: []string{"--link", fmt.Sprintf("%s:%s", kernelPath, "/vmlinuz")}},
	}, nil
}
