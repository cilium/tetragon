package cgroup

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/sensors/program"
	"golang.org/x/sys/unix"
)

const (
	fgsCgroupPath = "/run/tetragon/cgroup2"
)

var (
	fgsCgroupFD = -1
)

func LoadSockOpt(
	bpfDir, mapDir, ciliumDir string,
	load *program.Program,
) error {
	return LoadCgroupProgram(bpfDir, mapDir, ciliumDir, load)
}

func LoadCgroupProgram(
	bpfDir, mapDir, ciliumDir string,
	load *program.Program) error {
	if fgsCgroupFD < 0 {
		fd, err := unix.Open(fgsCgroupPath, unix.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err)
		}
		fgsCgroupFD = fd
	}
	return program.LoadProgram(bpfDir, []string{mapDir, ciliumDir}, load, program.RawAttach(fgsCgroupFD))
}
