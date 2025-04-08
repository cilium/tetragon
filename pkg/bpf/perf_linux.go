// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func UpdateElementFromPointers(fd int, structPtr, sizeOfStruct uintptr) error {
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_UPDATE_ELEM,
		structPtr,
		sizeOfStruct,
	)
	if ret != 0 || err != 0 {
		return fmt.Errorf("unable to update element for map with file descriptor %d: %s", fd, err)
	}
	return nil
}
