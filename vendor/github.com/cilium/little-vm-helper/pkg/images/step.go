// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import "github.com/cilium/little-vm-helper/pkg/slogger"

// StepConf is common step configuration
type StepConf struct {
	imagesDir string
	imgCnf    *ImgConf
	log       slogger.Logger
}
