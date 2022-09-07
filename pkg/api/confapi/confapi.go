// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package confapi

type TetragonConf struct {
	TgCgrpHierarchy uint32 `align:"tg_cgrp_hierarchy"`  // Tetragon Cgroup tracking hierarchy ID
	TgCgrpSubsysIdx uint32 `align:"tg_cgrp_subsys_idx"` // Tracking Cgroup css idx at compile time
}
