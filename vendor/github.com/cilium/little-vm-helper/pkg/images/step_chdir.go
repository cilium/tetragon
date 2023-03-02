// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"context"
	"os"

	"github.com/hashicorp/packer-plugin-sdk/multistep"
)

type ChdirStep struct {
	*StepConf
	Dir    string
	oldDir string
}

func NewChdirStep(cnf *StepConf, dir string) *ChdirStep {
	return &ChdirStep{
		StepConf: cnf,
		Dir:      dir,
	}
}

func (s *ChdirStep) Run(_ context.Context, _ multistep.StateBag) multistep.StepAction {
	var err error
	s.oldDir, err = os.Getwd()
	if err != nil {
		s.log.Warnf("failed to get current directory: %v", err)
		return multistep.ActionHalt
	}

	err = os.Chdir(s.Dir)
	if err != nil {
		s.log.Warnf("failed to get change directory: %v", err)
		return multistep.ActionHalt
	}
	s.log.Infof("set current working dir to '%s'", s.Dir)
	return multistep.ActionContinue
}

func (s *ChdirStep) Cleanup(_ multistep.StateBag) {
	err := os.Chdir(s.oldDir)
	if err != nil {
		s.log.Warnf("failed to get change to old directory: %v", err)
	}
}
