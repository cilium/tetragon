// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package defaults

const (
	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultMapPrefix is the default path prefix where Tetragon maps should be pinned
	DefaultMapPrefix = "tetragon"

	// DefaultEventMap is the default name of the Event map
	DefaultEventMap = "tcpmon"

	// DefaultMapRootFallback is the path which is used when /sys/fs/bpf has
	// a mount, but with the other filesystem than BPFFS.
	DefaultMapRootFallback = "/run/cilium/bpffs"

	// DefaultRunDir is the default run directory for runtime
	DefaultRunDir = "/var/run/tetragon/"

	// Default Path to where cgroup2 is mounted (Prefix with /run)
	Cgroup2Dir = "/run/tetragon/cgroup2"

	// DedfaultNetnsDir is the default network namespace directory for runtime
	DefaultNetnsDir = "/var/run/docker/netns/"

	// Default kernel exposed BTF file path
	DefaultBTFFile = "/sys/kernel/btf/vmlinux"

	// Default location for BPF programs and BTF files
	DefaultTetragonLib = "/var/lib/tetragon/"

	// InitInfoFile is the file location for the info file.
	// After initialization, InitInfoFile will contain a json representation of InitInfo
	// Used by both client cli to guess unix socket address and by bugtool
	InitInfoFile = DefaultRunDir + "tetragon-info.json"
)

var (
	// NetnsDir is the network namespace directory for runtime
	NetnsDir = DefaultNetnsDir
)
