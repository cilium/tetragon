// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

var (
	// Binaries used
	// Debootstrap = "debootstrap"
	Mmdebstrap    = "mmdebstrap"
	QemuImg       = "qemu-img"
	VirtCustomize = "virt-customize"
	GuestFish     = "guestfish"

	Binaries = []string{
		Mmdebstrap,
		QemuImg,
		VirtCustomize,
		GuestFish,
	}

	DefaultConfFile  = "images.json"
	DefaultImageSize = "8G"
)
