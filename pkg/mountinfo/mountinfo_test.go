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

// Copied from pkg/bpf/bpffs_linux.go. The reason it was not exported inside
// and used here is because importing that package would introduce an import
// cycle.
func mountFS(root, kind string) error {
	mapRootStat, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(root, 0755); err != nil {
				return fmt.Errorf("unable to create %s mount directory: %s", kind, err)
			}
		} else {
			return fmt.Errorf("failed to stat the mount path %s: %s", root, err)

		}
	} else if !mapRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", root)
	}

	if err := syscall.Mount(root, root, kind, 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s %s: %s", root, kind, err)
	}
	return nil
}
