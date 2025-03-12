// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSaveAndLoad(t *testing.T) {

	tmpFile, err := os.CreateTemp(t.TempDir(), "tetragon-bugtool-test-")
	if err != nil {
		t.Error("failed to create temporary file")
	}
	defer assert.NoError(t, tmpFile.Close())

	info1 := InitInfo{
		ExportFname: "1",
		LibDir:      "2",
		BTFFname:    "3",
		ServerAddr:  "",
		MetricsAddr: "foo",
	}

	if err := doSaveInitInfo(tmpFile.Name(), &info1); err != nil {
		t.Errorf("failed to save info: %s", err)
	}

	info2, err := doLoadInitInfo(tmpFile.Name())
	if err != nil {
		t.Errorf("failed to load info: %s", err)
	}

	if !reflect.DeepEqual(&info1, info2) {
		t.Errorf("mismatching structures: %v vs %v", info1, info2)
	}

	t.Log("Success")
}

func Test_findCgroupMountPath(t *testing.T) {
	const cgroupMountsHybrid = `tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
pstore /sys/fs/pstore pstore rw,nosuid,nodev,noexec,relatime 0 0
efivarfs /sys/firmware/efi/efivars efivarfs rw,nosuid,nodev,noexec,relatime 0 0
none /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup rw,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/rdma cgroup rw,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=351 0 0`

	const cgroupMountsLegacy = `tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
efivarfs /sys/firmware/efi/efivars efivarfs rw,nosuid,nodev,noexec,relatime 0 0
none /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup rw,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/rdma cgroup rw,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=351 0 0`

	const cgroupMountsUnified = `tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k,inode64 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
pstore /sys/fs/pstore pstore rw,nosuid,nodev,noexec,relatime 0 0
bpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0`

	type args struct {
		r          io.Reader
		unified    bool
		controller string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"cgroupv1_hybrid",
			args{strings.NewReader(cgroupMountsHybrid), false, "memory"},
			"/sys/fs/cgroup/memory",
			false,
		},
		{
			"cgroupv2_hybrid",
			args{strings.NewReader(cgroupMountsHybrid), true, ""},
			"/sys/fs/cgroup/unified",
			false,
		},
		{
			"cgroupv2",
			args{strings.NewReader(cgroupMountsUnified), true, ""},
			"/sys/fs/cgroup",
			false,
		},
		{
			"cgroupv1",
			args{strings.NewReader(cgroupMountsLegacy), false, "freezer"},
			"/sys/fs/cgroup/freezer",
			false,
		},
		{
			"cgroupv2_missing_legacy",
			args{strings.NewReader(cgroupMountsLegacy), true, ""},
			"",
			true,
		},
		{
			"cgroupv1_missing_unified",
			args{strings.NewReader(cgroupMountsUnified), false, "devices"},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findCgroupMountPath(tt.args.r, tt.args.unified, tt.args.controller)
			if (err != nil) != tt.wantErr {
				t.Errorf("findCgroupMountPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("findCgroupMountPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findMemoryCgroupPath(t *testing.T) {
	tests := []struct {
		name    string
		args    io.Reader
		want    bool
		want1   string
		wantErr bool
	}{
		{
			"cgroupv2",
			strings.NewReader("0::/user.slice/user-501.slice/session-92.scope"),
			true,
			"/user.slice/user-501.slice/session-92.scope",
			false,
		},
		{
			"cgroupv1",
			strings.NewReader(`2:cpuset:/
11:pids:/user.slice/user-501.slice/session-2.scope
10:blkio:/user.slice
9:rdma:/
8:freezer:/
7:cpu,cpuacct:/user.slice
6:devices:/user.slice
5:net_cls,net_prio:/
4:perf_event:/
3:memory:/user.slice/user-501.slice/session-2.scope
2:hugetlb:/
1:name=systemd:/user.slice/user-501.slice/session-2.scope`),
			false,
			"/user.slice/user-501.slice/session-2.scope",
			false,
		},
		{
			"cgroupv1_hybrid",
			strings.NewReader(`2:cpuset:/
11:pids:/user.slice/user-501.slice/session-2.scope
10:blkio:/user.slice
9:rdma:/
8:freezer:/
7:cpu,cpuacct:/user.slice
6:devices:/user.slice
5:net_cls,net_prio:/
4:perf_event:/
3:memory:/user.slice/user-501.slice/session-2.scope
2:hugetlb:/
1:name=systemd:/user.slice/user-501.slice/session-2.scope
0::/user.slice/user-501.slice/session-3.scope`),
			false,
			"/user.slice/user-501.slice/session-2.scope",
			false,
		},
		{
			"cgroupv1_hybrid",
			// this situation is artificial and I'm not sure it can happen in real life
			strings.NewReader(`2:cpuset:/
0::/user.slice/user-501.slice/session-3.scope
11:pids:/user.slice/user-501.slice/session-2.scope
10:blkio:/user.slice
9:rdma:/
8:freezer:/
7:cpu,cpuacct:/user.slice
6:devices:/user.slice
5:net_cls,net_prio:/
4:perf_event:/
3:memory:/user.slice/user-501.slice/session-2.scope
2:hugetlb:/
1:name=systemd:/user.slice/user-501.slice/session-2.scope`),
			false,
			"/user.slice/user-501.slice/session-2.scope",
			false,
		},
		{
			"empty",
			strings.NewReader(""),
			false,
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := findMemoryCgroupPath(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("findMemoryCgroupPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("findMemoryCgroupPath() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("findMemoryCgroupPath() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
