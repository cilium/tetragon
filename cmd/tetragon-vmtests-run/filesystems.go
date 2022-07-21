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
	fsId := fmt.Sprintf("%s_id", fs.id)
	tag := fmt.Sprintf("%s_tag", fs.id)
	return []string{
		"-fsdev", fmt.Sprintf("local,id=%s,path=%s,security_model=none", fsId, fs.hostdir),
		"-device", fmt.Sprintf("virtio-9p-pci,fsdev=%s,mount_tag=%s", fsId, tag),
	}
}

func (fs *virtIOFilesystem) fstabEntry() string {
	tag := fmt.Sprintf("%s_tag", fs.id)
	return fmt.Sprintf("%s\t%s\t9p\ttrans=virtio,rw\t0\t0\n", tag, fs.vmdir)
}
