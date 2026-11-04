// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package lvh

import "fmt"

// QemuFS is a filesystem shared with the VM.
type QemuFS interface {
	QemuArgs() []string
	FstabEntry() string
	VMMountpoint() string
}

// VirtIOFS shares a host directory with the VM over virtio-9p.
type VirtIOFS struct {
	ID      string
	HostDir string
	VMDir   string
}

func (fs *VirtIOFS) VMMountpoint() string {
	return fs.VMDir
}

func (fs *VirtIOFS) QemuArgs() []string {
	fsID := fs.ID + "_id"
	tag := fs.ID + "_tag"
	return []string{
		"-fsdev", fmt.Sprintf("local,id=%s,path=%s,security_model=none", fsID, fs.HostDir),
		"-device", fmt.Sprintf("virtio-9p-pci,fsdev=%s,mount_tag=%s", fsID, tag),
	}
}

func (fs *VirtIOFS) FstabEntry() string {
	tag := fs.ID + "_tag"
	return fmt.Sprintf("%s\t%s\t9p\ttrans=virtio,rw\t0\t0\n", tag, fs.VMDir)
}
