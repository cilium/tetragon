// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"github.com/cilium/tetragon/pkg/vmtests"
	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

type GoTestConf struct {
	lvh.Conf
	testerConf      vmtests.Conf
	detailedResults bool
	keepAllLogs     bool
}
