// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import "time"

const (
	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = `C:\Program Files\ebpf-for-windows`

	// DefaultMapPrefix is the default path prefix where Tetragon maps should be pinned
	DefaultMapPrefix = "tetragon"

	// DefaultEventMap is the default name of the Event map
	DefaultEventMap = "tcpmon"

	// DefaultMapRootFallback is the path which is used when /sys/fs/bpf has
	// a mount, but with the other filesystem than BPFFS.
	DefaultMapRootFallback = `C:\Program Files\Tetragon\bpffs`

	// DefaultRunDir is the default run directory for runtime
	DefaultRunDir = `C:\Program Files\Tetragon\`

	// Default Path to where cgroup2 is mounted (Prefix with /run)
	Cgroup2Dir = ""

	// Default location for BPF programs and BTF files
	DefaultTetragonLib = `C:\Program Files\Tetragon\BPF`

	// InitInfoFile is the file location for the info file.
	// After initialization, InitInfoFile will contain a json representation of InitInfo
	// Used by both client cli to guess unix socket address and by bugtool
	InitInfoFile = DefaultRunDir + "tetragon-info.json"

	// Default directory from where to load tracing policies.
	DefaultTpDir = DefaultRunDir + "tetragon.tp.d"

	// Default secure export logs permissions
	DefaultLogsPermission = "600"

	// Pid file where to write tetragon main PID
	DefaultPidFile = DefaultRunDir + "tetragon.pid"

	// defaults for the event cache
	DefaultEventCacheNumRetries = 15
	DefaultEventCacheRetryDelay = 2

	// defaults for the process cache
	DefaultProcessCacheGCInterval = 30 * time.Second
)
