// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package confapi

type TetragonConf struct {
	Mode        uint32 // Deployment mode
	LogLevel    uint32 // Tetragon log level
	PID         uint32 // Tetragon PID for debugging purpose
	NSPID       uint32 // Tetragon PID in namespace for debugging purpose
	TgCgrpLevel uint32 // Tetragon cgroup level
	Pad         uint32
	TgCgrpId    uint64 // Tetragon cgroup ID
	CgrpFsMagic uint64 // Cgroupv1 or cgroupv2
}
