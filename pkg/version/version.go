// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package version

import (
	"fmt"
	"runtime/debug"
)

var Version string
var Name string

type BuildInfo struct {
	GoVersion string
	Commit    string
	Time      string
	Modified  string
}

func ReadBuildInfo() *BuildInfo {
	info := &BuildInfo{}
	buildInfo, ok := debug.ReadBuildInfo()
	if ok {
		info.GoVersion = buildInfo.GoVersion
		// unfortunately, it's not a Go map
		for _, s := range buildInfo.Settings {
			if s.Key == "vcs.revision" {
				info.Commit = s.Value
				continue
			}
			if s.Key == "vcs.time" {
				info.Time = s.Value
				continue
			}
			if s.Key == "vcs.modified" {
				info.Modified = s.Value
				continue
			}
		}
	}
	return info
}

func (info BuildInfo) Print() {
	if info.GoVersion != "" {
		fmt.Printf("GoVersion: %s\n", info.GoVersion)
	}
	if info.Time != "" {
		fmt.Printf("Date: %s\n", info.Time)
	}
	if info.Commit != "" {
		fmt.Printf("GitCommit: %s\n", info.Commit)
	}
	if info.Modified != "" {
		var state string
		if info.Modified == "true" {
			state = "dirty"
		} else {
			state = "clean"
		}
		fmt.Printf("GitTreeState: %s\n", state)
	}
}
