// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/cilium/tetragon/pkg/alignchecker"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/checkprocfs"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"

	"github.com/spf13/viper"
)

func logCurrentSecurityContext() {
	proc.LogCurrentSecurityContext()
}

func initHostNamespaces() error {
	_, err := namespace.InitHostNamespace()
	return err
}

func checkProcFS() {
	checkprocfs.Check()
}

func initCachedBTF(lib, btfString string) error {
	return btf.InitCachedBTF(lib, btfString)
}

func checkStructAlignments() error {
	path, err := config.FindProgramFile("bpf_alignchecker.o")
	if err != nil {
		return err
	}
	return alignchecker.CheckStructAlignmentsDefault(path)
}

func setNetNSDir() {
	if viper.IsSet(option.KeyNetnsDir) {
		defaults.NetnsDir = viper.GetString(option.KeyNetnsDir)
	}
}
