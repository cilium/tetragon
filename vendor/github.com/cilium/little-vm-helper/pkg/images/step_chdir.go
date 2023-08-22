// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"context"
	"os"

	"github.com/cilium/little-vm-helper/pkg/step"
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

func (s *ChdirStep) Do(ctx context.Context) (step.Result, error) {
	var err error
	s.oldDir, err = os.Getwd()
	if err != nil {
		s.log.Warnf("failed to get current directory: %v", err)
		return step.Stop, err
	}

	err = os.Chdir(s.Dir)
	if err != nil {
		s.log.Warnf("failed to get change directory: %v", err)
		return step.Stop, err
	}
	s.log.Infof("set current working dir to '%s'", s.Dir)
	return step.Continue, nil
}

func (s *ChdirStep) Cleanup(ctx context.Context) {
	err := os.Chdir(s.oldDir)
	if err != nil {
		s.log.Warnf("failed to get change to old directory: %v", err)
	}
}
