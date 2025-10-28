// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/option"
)

var bpffsReady bool

// NB: there is an import cycle that does allow us to use testutils.RepoRootPath
func repoRootPath() string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..")
}

func initBpffs() string {
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountTraceFS()
	bpf.ConfigureResourceLimits()
	dirPath, err := os.MkdirTemp(defaults.DefaultMapRoot, "test-policy-filter-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup bpf map root: %s\n", err)
		return ""
	}
	dir := filepath.Base(dirPath)
	bpf.SetMapPrefix(dir)
	bpffsReady = true
	return dirPath
}

func TestMain(m *testing.M) {
	flag.StringVar(&option.Config.HubbleLib,
		"bpf-lib", filepath.Join(repoRootPath(), "bpf", "objs"),
		"tetragon lib directory (location of btf file and bpf objs).")
	flag.Parse()

	if envLib := os.Getenv("TETRAGON_LIB"); envLib != "" {
		option.Config.HubbleLib = envLib
	}

	// setup a custom bpffs path to pin objects
	dirPath := initBpffs()

	ec := m.Run()

	// cleanup bpffs path
	if dirPath != "" {
		os.RemoveAll(dirPath)
	}

	os.Exit(ec)
}
