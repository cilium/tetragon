// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package lvh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/cilium/little-vm-helper/pkg/slogger"
	"github.com/cilium/little-vm-helper/pkg/step"
)

// FilesystemActions mounts the shared filesystems in the image through fstab.
func FilesystemActions(fs []QemuFS, tmpDir string) ([]images.Action, error) {
	actions := make([]images.Action, 0, len(fs)+1)

	var b bytes.Buffer
	for _, fs := range fs {
		b.WriteString(fs.FstabEntry())
		act := images.Action{
			Op: &images.MkdirCommand{Dir: fs.VMMountpoint()},
		}
		actions = append(actions, act)
	}

	// NB: this is so that init can remount / rw
	b.WriteString("/dev/root\t/\text4\terrors=remount-ro\t0\t1\n")

	tmpFile := filepath.Join(tmpDir, "fstab")
	err := os.WriteFile(tmpFile, b.Bytes(), 0722)
	if err != nil {
		return nil, err
	}

	actions = append(actions, images.Action{
		Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: "/etc",
		},
	})

	return actions, nil
}

var networkConf = `
[Match]
Name=ens* enp* eth*
[Network]
DHCP=yes
`

// NetActions enables networking and root login over ssh in the image.
func NetActions(tmpDir string) ([]images.Action, error) {
	ret := []images.Action{
		// Allow easy login for root user from ssh
		{Op: &images.AppendLineCommand{
			File: "/etc/ssh/sshd_config",
			Line: "PermitRootLogin yes",
		}},
		{Op: &images.AppendLineCommand{
			File: "/etc/ssh/sshd_config",
			Line: "PermitEmptyPasswords yes",
		}},
	}

	var b bytes.Buffer
	b.WriteString(networkConf)
	base := "20-interfaces.network"
	tmpFile := filepath.Join(tmpDir, base)
	err := os.WriteFile(tmpFile, b.Bytes(), 0644)
	if err != nil {
		return nil, err
	}

	dstDir := "/etc/systemd/network"
	ret = append(ret,
		images.Action{Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: dstDir,
		}},
		images.Action{Op: &images.ChmodCommand{
			File:        filepath.Join(dstDir, base),
			Permissions: "0644",
		}},
		images.Action{Op: &images.RunCommand{
			Cmd: "systemctl enable systemd-networkd.service",
		}},
	)

	return ret, nil
}

// noNetworkCommand runs virt-customize without network access.
type noNetworkCommand struct{}

func (rc *noNetworkCommand) ActionOpName() string {
	return "no-network"
}

func (rc *noNetworkCommand) ToSteps(s *images.StepConf) ([]step.Step, error) {
	return []step.Step{&images.VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--no-network"},
	}}, nil
}

// BaseActions returns the actions every test image starts with.
func BaseActions(cnf *Conf) []images.Action {
	return []images.Action{
		{Op: &noNetworkCommand{}},
		{Op: &images.SetHostnameCommand{Hostname: cnf.VMName}},
		{Op: &images.AppendLineCommand{
			File: "/etc/sysctl.d/local.conf",
			Line: "kernel.panic_on_rcu_stall=1",
		}},
	}
}

// BTFAction copies the BTF file into the image and returns its path there.
func BTFAction(btfFile string) (images.Action, string, error) {
	absBTFFile, err := filepath.Abs(btfFile)
	if err != nil {
		return images.Action{}, "", fmt.Errorf("failed to get btf file full path: %w", err)
	}
	return images.Action{
		Op: &images.CopyInCommand{
			LocalPath: absBTFFile,
			RemoteDir: "/boot/",
		},
	}, "/boot/" + filepath.Base(btfFile), nil
}

// BuildImage builds the test image from the base image with actions.
func BuildImage(log slogger.Logger, cnf *Conf, actions []images.Action, forceRebuild bool) error {
	imagesDir, baseImage := filepath.Split(cnf.BaseImageFilename)
	icnf := images.ImagesConf{
		Dir: imagesDir,
		// TODO: might be useful to modify the images builder so that
		// we can build this image using qemu-img -b
		Images: []images.ImgConf{{
			Name:    cnf.imageFilename(),
			Parent:  baseImage,
			Actions: actions,
		}},
	}

	forest, err := images.NewImageForest(&icnf, false)
	if err != nil {
		return fmt.Errorf("failed to set up the image build: %w", err)
	}

	res := forest.BuildAllImages(&images.BuildConf{
		Log:          log,
		DryRun:       false,
		ForceRebuild: forceRebuild,
		MergeSteps:   true,
	})

	return res.Err()
}
