// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"context"
	"fmt"
	"os/exec"
	"path"

	"github.com/cilium/little-vm-helper/pkg/logcmd"
	"github.com/cilium/little-vm-helper/pkg/step"
)

// VirtCustomizeStep is a step implemented a set of arguments in virt-customize
//
// NB: we can maybe merge multiple VirtCustomizeStep in a single virt-customize invocation.
// The idea here would be that virt-customize performs the actions in its
// arguments sequentially.
//
// NB: we can probably do the same with guestfish as well
type VirtCustomizeStep struct {
	*StepConf
	Args []string
}

func (s *VirtCustomizeStep) Do(ctx context.Context) (step.Result, error) {
	imgFname := path.Join(s.imagesDir, s.imgCnf.Name)
	args := []string{"-a", imgFname}
	args = append(args, s.Args...)
	cmd := exec.CommandContext(ctx, "virt-customize", args...)
	err := logcmd.RunAndLogCommand(cmd, s.log)
	if err != nil {
		s.log.WithField("image", s.imgCnf.Name).WithError(err).Error("error executing command")
		return step.Stop, err
	}

	return step.Continue, nil
}

func (s *VirtCustomizeStep) Cleanup(ctx context.Context) {
}

func (s *VirtCustomizeStep) Merge(step step.Step) error {
	vcs, ok := step.(*VirtCustomizeStep)
	if !ok {
		return fmt.Errorf("type %T cannot be merged to a VirtCustomizeStep", step)
	}

	if vcs.StepConf != s.StepConf {
		return fmt.Errorf("acttions with different step configurations cannnot be merged (%v vs %v)", s.StepConf, vcs.StepConf)
	}

	s.Args = append(s.Args, vcs.Args...)
	return nil
}
