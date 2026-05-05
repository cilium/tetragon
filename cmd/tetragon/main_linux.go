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
	"github.com/cilium/tetragon/pkg/server"

	"github.com/spf13/viper"
)

// defaultUnixSocketPath is the in-pod IPC socket. tetragon-info.json
// advertises it so co-located tooling does not have to ship TLS material.
const defaultUnixSocketPath = "/var/run/tetragon/tetragon.sock"

// resolveUnixSocketPath returns the unix socket path the agent should
// expose for in-pod tooling and whether one should be started, derived
// from listenAddr: a "unix://X" address yields X; a TCP address yields
// defaultUnixSocketPath; an empty or invalid address yields ("", false).
func resolveUnixSocketPath(listenAddr string) (string, bool) {
	if listenAddr == "" {
		return "", false
	}
	proto, addr, err := server.SplitListenAddr(listenAddr)
	if err != nil {
		return "", false
	}
	if proto == "unix" {
		return addr, true
	}
	return defaultUnixSocketPath, true
}

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
