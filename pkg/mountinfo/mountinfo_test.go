// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package mountinfo

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestIsMountFS(t *testing.T) {
	type args struct {
		infos     []*MountInfo
		typ, root string
	}
	type want struct {
		mounted, instance bool
	}
	tests := []struct {
		name            string
		args            args
		want            want
		preRun, postRun func()
	}{
		{
			name: "/sys/fs/bpf empty directory",
			args: args{
				infos: []*MountInfo{
					{
						Root:           "/",
						MountPoint:     "/tmp/sys/fs/bpf",
						FilesystemType: FilesystemTypeBPFFS,
					},
				},
				typ:  FilesystemTypeBPFFS,
				root: "/tmp/sys/fs/bpf",
			},
			want: want{
				mounted:  true,
				instance: true,
			},
			preRun: func() {
				mountFS("/tmp/sys/fs/bpf", FilesystemTypeBPFFS)
			},
			postRun: func() {
				syscall.Unmount("/tmp/sys/fs/bpf", 0)
				syscall.Rmdir("/tmp/sys/fs/bpf")
				syscall.Rmdir("/tmp/sys/fs")
				syscall.Rmdir("/tmp/sys")
			},
		},
		{
			name: "/sys/fs/bpf not mounted",
			args: args{
				infos: []*MountInfo{
					{},
				},
				typ:  FilesystemTypeBPFFS,
				root: "/sys/fs/bpf",
			},
			want: want{
				mounted:  false,
				instance: false,
			},
			preRun:  func() {},
			postRun: func() {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.preRun()
			defer tt.postRun()
			m, i := IsMountFS(tt.args.infos, tt.args.typ, tt.args.root)
			infos, _ := GetMountInfo()
			for _, v := range infos {
				fmt.Printf("%+v\n", *v)
			}
			switch {
			case m != tt.want.mounted, m != tt.want.instance:
				t.Errorf("IsMountFS() = got (%v,%v), want (%v,%v)",
					m, i, tt.want.mounted, tt.want.instance)
			}
		})
	}
}

func TestCgroup2SuperOptions(t *testing.T) {
	tests := []struct {
		name     string
		infos    []*MountInfo
		expected string
	}{
		{
			name: "cgroup2 with nsdelegate and memory_recursiveprot",
			infos: []*MountInfo{
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "rw,nsdelegate,memory_recursiveprot",
				},
			},
			expected: "nsdelegate,memory_recursiveprot",
		},
		{
			name: "cgroup2 with ro and other flags",
			infos: []*MountInfo{
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "ro,nsdelegate",
				},
			},
			expected: "nsdelegate",
		},
		{
			name: "cgroup2 only rw",
			infos: []*MountInfo{
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "rw",
				},
			},
			expected: "",
		},
		{
			name: "cgroup2 with empty SuperOptions",
			infos: []*MountInfo{
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "",
				},
			},
			expected: "",
		},
		{
			name: "multiple cgroup2 entries uses the first cgroup2 entry",
			infos: []*MountInfo{
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "rw,nsdelegate",
				},
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "rw,other_opt",
				},
			},
			expected: "nsdelegate",
		},
		{
			name: "no cgroup2 entry",
			infos: []*MountInfo{
				{
					FilesystemType: FilesystemTypeBPFFS,
					SuperOptions:   "rw,relatime",
				},
			},
			expected: "",
		},
		{
			name: "skips cgroup2 entry with only rw and picks the one with options",
			infos: []*MountInfo{
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "rw",
				},
				{
					FilesystemType: FilesystemTypeCgroup2,
					SuperOptions:   "rw,nsdelegate,memory_recursiveprot",
				},
			},
			expected: "nsdelegate,memory_recursiveprot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Cgroup2SuperOptions(tt.infos)
			if got != tt.expected {
				t.Errorf("Cgroup2SuperOptions() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// Copied from pkg/bpf/bpffs_linux.go. The reason it was not exported inside
// and used here is because importing that package would introduce an import
// cycle.
func mountFS(root, kind string) error {
	mapRootStat, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(root, 0755); err != nil {
				return fmt.Errorf("unable to create %s mount directory: %w", kind, err)
			}
		} else {
			return fmt.Errorf("failed to stat the mount path %s: %w", root, err)

		}
	} else if !mapRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", root)
	}

	if err := syscall.Mount(root, root, kind, 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s %s: %w", root, kind, err)
	}
	return nil
}
