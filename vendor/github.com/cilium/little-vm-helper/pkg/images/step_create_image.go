// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/little-vm-helper/pkg/logcmd"
	"github.com/cilium/little-vm-helper/pkg/step"
	"github.com/sirupsen/logrus"
)

var (
	// DelImageIfExists: if set to true, image will be deleted at Cleanup() by the CreateImage step
	DelImageIfExists = "DelImageIfExist"

	rootDev    = "/dev/vda"
	rootFsType = "ext4"
	resizeFS   = "resize2fs"
)

// Approach for creating images:
// - Base (root) images are build using mmdebstrap and copying files using guestfish.
// - Non-root images are build using virt-customize, by copying the parent.
// - All images use the raw format (not qcow2)
// - Images are read-only. Users can use them to create other images (by copying or via qcow2)
//
// Alternative options I considred and may be useful for future reference:
//  - using qemu-nbd+chroot, would probably be a faster way to do this, but it requires root.
//  - using either debootstrap, or multistrap (with fakeroot and fakechroot) instead of mmdebstrap.
//    The latter seems faster, so I thought I'd use it. If something breaks, we can always go another
//    route.
//  - using the go bindings for libguestfs (https://libguestfs.org/guestfs-golang.3.html). Using the
//    CLI seemed simpler.
//  - having bootable images. I don't think we need this since we can specify --kernel and friends
//    in qemu.
//  - having the images in qcow2 so that we save some space. I think the sparsity of the files is
//    enough, so decided to keep things simple. Note that we can use virt-sparsify if we want to (e.g.,
//    when downloading images).

// CreateImage is a step for creating an image. Its cleanup will delete the image if DelImageIfExists is set.

type CreateImage struct {
	*StepConf
	bootable bool
}

func NewCreateImage(cnf *StepConf) *CreateImage {
	return &CreateImage{
		StepConf: cnf,
		// NB(kkourt): for now all the images we create are bootable because we can always
		// boot them by directly specifing -kernel in qemu. Kept this, however, in case at
		// some point we want to change it. Note, also, that because all images are
		// bootable, it is sufficient to do create root bootable images.
		bootable: true,
	}
}

var extLinuxConf = fmt.Sprintf(`
default linux
timeout 0

label linux
kernel /vmlinuz
append initrd=initrd.img root=%s rw console=ttyS0
`, rootDev)

// makeRootImage creates a root (with respect to the image forest hierarch) image
func (s *CreateImage) makeRootImage(ctx context.Context) error {
	imgFname := filepath.Join(s.imagesDir, s.imgCnf.Name)
	tarFname := path.Join(s.imagesDir, fmt.Sprintf("%s.tar", s.imgCnf.Name))
	// build package list: add a kernel if building a bootable image
	packages := make([]string, 0, len(s.imgCnf.Packages)+1)
	if s.bootable {
		packages = append(packages, "linux-image-amd64")
	}
	packages = append(packages, s.imgCnf.Packages...)

	cmd := exec.CommandContext(ctx, Mmdebstrap,
		"sid",
		"--include", strings.Join(packages, ","),
		tarFname,
	)
	err := logcmd.RunAndLogCommand(cmd, s.log)
	if err != nil {
		return err
	}
	defer func() {
		err := os.Remove(tarFname)
		if err != nil {
			s.log.WithError(err).Info("failed to remove tarfile")
		}
	}()

	imgSize := DefaultImageSize
	if size := s.imgCnf.ImageSize; size != "" {
		imgSize = size
	}

	// example: guestfish -N foo.img=disk:8G -- mkfs ext4 /dev/vda : mount /dev/vda / : tar-in /tmp/foo.tar /
	if s.bootable {
		dirname, err := os.MkdirTemp("", "extlinux-")
		if err != nil {
			return err
		}
		defer func() {
			os.RemoveAll(dirname)
		}()
		fname := filepath.Join(dirname, "extlinux.conf")
		if err := os.WriteFile(fname, []byte(extLinuxConf), 0722); err != nil {
			return err
		}

		cmd = exec.CommandContext(ctx, GuestFish,
			"-N", fmt.Sprintf("%s=disk:%s", imgFname, imgSize),
			"--",
			"part-disk", rootDev, "mbr",
			":",
			"part-set-bootable", rootDev, "1", "true",
			":",
			"mkfs", rootFsType, rootDev,
			":",
			"mount", rootDev, "/",
			":",
			"tar-in", tarFname, "/",
			":",
			"extlinux", "/",
			":",
			"copy-in", fname, "/",
		)
	} else {
		cmd = exec.CommandContext(ctx, GuestFish,
			"-N", fmt.Sprintf("%s=disk:%s", imgFname, imgSize),
			"--",
			"mkfs", rootFsType, rootDev,
			":",
			"mount", rootDev, "/",
			":",
			"tar-in", tarFname, "/",
		)
	}

	if err := logcmd.RunAndLogCommand(cmd, s.log); err != nil {
		return err
	}

	if imageFormatFromFname(imgFname) == "qcow2" {
		tmpImage := fmt.Sprintf("%s.img", imgFname)
		if err := os.Rename(imgFname, tmpImage); err != nil {
			return err
		}
		defer os.Remove(tmpImage)
		cmd := exec.CommandContext(ctx, QemuImg, "convert", "-f", "raw", "-O", "qcow2", tmpImage, imgFname)
		return logcmd.RunAndLogCommand(cmd, s.log)
	}

	return nil

}

func resizeImage(ctx context.Context,
	log logrus.FieldLogger,
	imgFname string, size string,
) error {

	// resize image
	cmd := exec.CommandContext(ctx, QemuImg, "resize", imgFname, size)
	err := logcmd.RunAndLogCommand(cmd, log)
	if err != nil {
		return err
	}

	// resize filesystem
	cmd = exec.CommandContext(ctx, GuestFish,
		"-a", imgFname,
		"--",
		"run",
		":",
		resizeFS,
		rootDev,
	)
	err = logcmd.RunAndLogCommand(cmd, log)
	if err != nil {
		return err
	}
	return nil
}

// makeDerivedImage creates a non-root image
func (s *CreateImage) makeDerivedImage(ctx context.Context) error {
	parFname := filepath.Join(s.imagesDir, s.imgCnf.Parent)
	imgFname := filepath.Join(s.imagesDir, s.imgCnf.Name)

	parFmt := imageFormatFromFname(parFname)
	imgFmt := imageFormatFromFname(imgFname)

	cmd := exec.CommandContext(ctx, QemuImg, "convert", "-f", parFmt, "-O", imgFmt, parFname, imgFname)
	err := logcmd.RunAndLogCommand(cmd, s.log)
	if err != nil {
		return err
	}

	// We could check whether the image is the same, but this is tricky.
	// The configuration of the parent does not always exist, so we would
	// have to check the current size of the image. To make life easier, we
	// always resize if the user defines a size.
	if size := s.imgCnf.ImageSize; size != "" {
		if err := resizeImage(ctx, s.log, imgFname, size); err != nil {
			return err
		}
	}

	if len(s.imgCnf.Packages) > 0 {
		cmd = exec.CommandContext(ctx, VirtCustomize,
			"-a", imgFname,
			"--install", strings.Join(s.imgCnf.Packages, ","),
		)
		return logcmd.RunAndLogCommand(cmd, s.log)
	}

	return nil
}

func (s *CreateImage) Do(ctx context.Context) (step.Result, error) {
	var err error
	if s.imgCnf.Parent == "" {
		err = s.makeRootImage(ctx)
	} else {
		err = s.makeDerivedImage(ctx)
	}

	if err != nil {
		s.log.WithField("image", s.imgCnf.Name).WithError(err).Error("error buiding image")
		return step.Stop, err
	}
	return step.Continue, nil
}

func (s *CreateImage) Cleanup(ctx context.Context) {
}
