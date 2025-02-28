// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"github.com/cilium/tetragon/pkg/api"
)

// TODO: Harmonize these with the API docs (Flags field in tetragon.Process)
var FlagStrings = map[uint32]string{
	api.EventExecve: "execve",
	// nolint We still want to support this even though it's deprecated
	api.EventExecveAt:              "execveat",
	api.EventProcFS:                "procFS",
	api.EventTruncFilename:         "truncFilename",
	api.EventTruncArgs:             "truncArgs",
	api.EventTaskWalk:              "taskWalk",
	api.EventMiss:                  "miss",
	api.EventNeedsAUID:             "auid",
	api.EventErrorFilename:         "errorFilename",
	api.EventErrorArgs:             "errorArgs",
	api.EventNoCWDSupport:          "nocwd",
	api.EventRootCWD:               "rootcwd",
	api.EventErrorCWD:              "errorCWD",
	api.EventClone:                 "clone",
	api.EventErrorCgroupName:       "errorCgroupName",
	api.EventErrorCgroupId:         "errorCgroupID",
	api.EventErrorCgroupKn:         "errorCgroupKn",
	api.EventErrorCgroupSubsysCgrp: "errorCgroupSubsysCgrp",
	api.EventErrorCgroupSubsys:     "errorCgroupSubsys",
	api.EventErrorCgroups:          "errorCgroups",
	api.EventErrorPathComponents:   "errorPathResolutionCwd",
	api.EventDataFilename:          "dataFilename",
	api.EventDataArgs:              "dataArgs",
	api.EventInInitTree:            "inInitTree",
}

var flagsOrdered = []uint32{
	api.EventExecve,
	// nolint We still want to support this even though it's deprecated
	api.EventExecveAt,
	api.EventProcFS,
	api.EventTruncFilename,
	api.EventTruncArgs,
	api.EventTaskWalk,
	api.EventMiss,
	api.EventNeedsAUID,
	api.EventErrorFilename,
	api.EventErrorArgs,
	api.EventNoCWDSupport,
	api.EventRootCWD,
	api.EventErrorCWD,
	api.EventClone,
	api.EventErrorCgroupName,
	api.EventErrorCgroupId,
	api.EventErrorCgroupKn,
	api.EventErrorCgroupSubsysCgrp,
	api.EventErrorCgroupSubsys,
	api.EventErrorCgroups,
	api.EventErrorPathComponents,
	api.EventDataFilename,
	api.EventDataArgs,
	api.EventInInitTree,
}

func DecodeCommonFlags(flags uint32) []string {
	var s []string
	for _, f := range flagsOrdered {
		v := FlagStrings[f]
		if (flags & f) != 0 {
			s = append(s, v)
		}
	}
	return s
}
