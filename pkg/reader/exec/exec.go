// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"syscall"

	"github.com/cilium/tetragon/pkg/api"
	"golang.org/x/sys/unix"
)

func DecodeCommonFlags(flags uint32) []string {
	var s []string
	if (flags & api.EventExecve) != 0 {
		s = append(s, "execve")
	}
	// nolint We still want to support this even though it's deprecated
	if (flags & api.EventExecveAt) != 0 {
		s = append(s, "execveat")
	}
	if (flags & api.EventProcFS) != 0 {
		s = append(s, "procFS")
	}
	if (flags & api.EventTruncFilename) != 0 {
		s = append(s, "truncFilename")
	}
	if (flags & api.EventTruncArgs) != 0 {
		s = append(s, "truncArgs")
	}
	if (flags & api.EventTaskWalk) != 0 {
		s = append(s, "taskWalk")
	}
	if (flags & api.EventMiss) != 0 {
		s = append(s, "miss")
	}
	if (flags & api.EventNeedsAUID) != 0 {
		s = append(s, "auid")
	}
	if (flags & api.EventErrorFilename) != 0 {
		s = append(s, "errorFilename")
	}
	if (flags & api.EventErrorArgs) != 0 {
		s = append(s, "errorArgs")
	}
	if (flags & api.EventNoCWDSupport) != 0 {
		s = append(s, "nocwd")
	}
	if (flags & api.EventRootCWD) != 0 {
		s = append(s, "rootcwd")
	}
	if (flags & api.EventErrorCWD) != 0 {
		s = append(s, "errorCWD")
	}
	if (flags & api.EventClone) != 0 {
		s = append(s, "clone")
	}
	if (flags & api.EventErrorCgroupName) != 0 {
		s = append(s, "errorCgroupName")
	}
	if (flags & api.EventErrorCgroupId) != 0 {
		s = append(s, "errorCgroupID")
	}
	if (flags & api.EventErrorCgroupKn) != 0 {
		s = append(s, "errorCgroupKn")
	}
	if (flags & api.EventErrorCgroupSubsysCgrp) != 0 {
		s = append(s, "errorCgroupSubsysCgrp")
	}
	if (flags & api.EventErrorCgroupSubsys) != 0 {
		s = append(s, "errorCgroupSubsys")
	}
	if (flags & api.EventErrorCgroups) != 0 {
		s = append(s, "errorCgroups")
	}
	if (flags & api.EventErrorPathComponents) != 0 {
		s = append(s, "errorPathResolutionCwd")
	}
	return s
}

func Signal(s uint32) string {
	if s == 0 {
		return ""
	}
	return unix.SignalName(syscall.Signal(s))
}
