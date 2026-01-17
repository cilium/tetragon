// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/slogger"
	"github.com/cilium/little-vm-helper/pkg/step"
)

// doBuildImageDryRun just creates an empty file for the image.
func (f *ImageForest) doBuildImageDryRun(image string) error {
	_, ok := f.confs[image]
	if !ok {
		return fmt.Errorf("building image '%s' failed, configuration not found", image)
	}

	fname := f.imageFilename(image)
	file, err := os.Create(fname)
	defer file.Close()

	return err
}

// merge act2 to act1, or return an error
func mergeSteps(step1, step2 step.Step) error {
	mergable, ok := step1.(interface {
		Merge(step step.Step) error
	})
	if !ok {
		return fmt.Errorf("step1 (%v) not mergable", step1)
	}

	if err := mergable.Merge(step2); err != nil {
		return err
	}

	return nil
}

func (f *ImageForest) doBuildImage(
	ctx context.Context,
	log slogger.Logger,
	image string,
	merge bool,
	pkgRepository string,
) error {
	cnf, ok := f.confs[image]
	if !ok {
		return fmt.Errorf("building image '%s' failed, configuration not found", image)
	}

	stepConf := &StepConf{
		imagesDir: f.imagesDir,
		imgCnf:    cnf,
		log:       log,
	}

	steps := make([]step.Step, 2, 2+len(cnf.Actions))

	steps[0] = NewCreateImage(stepConf, pkgRepository)
	// NB: We might need an --chdir option or similar, but for now just
	// chdir to the the base dir.
	baseDir, path := filepath.Split(f.imagesDir)
	steps[1] = NewChdirStep(stepConf, baseDir)

	// NB: after the chroot, we need to also change the images dir if it is a relative path for
	// the subsequent steps.
	if !filepath.IsAbs(stepConf.imagesDir) {
		stepConf = &StepConf{
			imagesDir: path,
			imgCnf:    cnf,
			log:       log,
		}
	}

	for i := 0; i < len(cnf.Actions); i++ {
		nextSteps, err := cnf.Actions[i].Op.ToSteps(stepConf)
		if err != nil {
			return fmt.Errorf("action %s ('%T') failed: %v", cnf.Actions[i].Comment, cnf.Actions[i].Op, err)
		}
		for _, next := range nextSteps {
			prev := steps[len(steps)-1]
			if merge && mergeSteps(prev, next) == nil {
				continue
			}
			steps = append(steps, next)
		}
	}

	err := step.DoSteps(ctx, steps)
	if err != nil {
		imgFname := f.imageFilename(image)
		log.Warnf("image file '%s' not deleted so that it can be inspected", imgFname)
		return err
	}
	return nil
}
