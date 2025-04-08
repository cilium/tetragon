// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import "fmt"

type QemuFS interface {
	qemuArgs() []string
	fstabEntry() string
	vmMountpoint() string
}

type virtIOFilesystem struct {
	id      string
	hostdir string
	vmdir   string
}

func (fs *virtIOFilesystem) vmMountpoint() string {
	return fs.vmdir
}

func (fs *virtIOFilesystem) qemuArgs() []string {
	fsId := fs.id + "_id"
	tag := fs.id + "_tag"
	return []string{
		"-fsdev", fmt.Sprintf("local,id=%s,path=%s,security_model=none", fsId, fs.hostdir),
		"-device", fmt.Sprintf("virtio-9p-pci,fsdev=%s,mount_tag=%s", fsId, tag),
	}
}

func (fs *virtIOFilesystem) fstabEntry() string {
	tag := fs.id + "_tag"
	return fmt.Sprintf("%s\t%s\t9p\ttrans=virtio,rw\t0\t0\n", tag, fs.vmdir)
}
