// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"github.com/cilium/tetragon/pkg/api"
)

// TODO: Harmonize these with the API docs (Flags field in tetragon.Process)
var FlagStrings = map[uint32]string{
	api.EventExecve:                "execve",
	api.EventProcFS:                "procFS",
	api.EventErrorEnvs:             "errorEnvs",
	api.EventTruncArgs:             "truncArgs",
	api.EventMiss:                  "miss",
	api.EventErrorFilename:         "errorFilename",
	api.EventErrorArgs:             "errorArgs",
	api.EventNoCWDSupport:          "nocwd",
	api.EventRootCWD:               "rootcwd",
	api.EventErrorCWD:              "errorCWD",
	api.EventClone:                 "clone",
	api.EventErrorCgroupName:       "errorCgroupName",
	api.EventErrorCgroupId:         "errorCgroupID",
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
	api.EventProcFS,
	api.EventErrorEnvs,
	api.EventTruncArgs,
	api.EventMiss,
	api.EventErrorFilename,
	api.EventErrorArgs,
	api.EventNoCWDSupport,
	api.EventRootCWD,
	api.EventErrorCWD,
	api.EventClone,
	api.EventErrorCgroupName,
	api.EventErrorCgroupId,
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
