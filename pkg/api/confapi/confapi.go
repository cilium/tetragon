// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package confapi

type TetragonConf struct {
	Mode            uint32 `align:"mode"`               // Deployment mode
	LogLevel        uint32 `align:"loglevel"`           // Tetragon log level
	PID             uint32 `align:"pid"`                // Tetragon PID for debugging purpose
	NSPID           uint32 `align:"nspid"`              // Tetragon PID in namespace for debugging purpose
	TgCgrpHierarchy uint32 `align:"tg_cgrp_hierarchy"`  // Tetragon Cgroup tracking hierarchy ID
	TgCgrpSubsysIdx uint32 `align:"tg_cgrp_subsys_idx"` // Tracking Cgroup css idx at compile time
	TgCgrpLevel     uint32 `align:"tg_cgrp_level"`      // Tetragon cgroup level
	Pad             uint32 `align:"pad"`                // Padded value
	TgCgrpId        uint64 `align:"tg_cgrpid"`          // Tetragon cgroup ID
	CgrpFsMagic     uint64 `align:"cgrp_fs_magic"`      // Cgroupv1 or cgroupv2
}
