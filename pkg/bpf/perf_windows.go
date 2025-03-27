// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"

	"golang.org/x/sys/windows"
)

var (
	EbpfApi = windows.NewLazyDLL("ebpfapi.dll")
	BPF     = EbpfApi.NewProc("bpf")
)

func UpdateElementFromPointers(fd int, structPtr, sizeOfStruct uintptr) error {

	ret, _, err := BPF.Call(BPF_MAP_LOOKUP_ELEM, structPtr, sizeOfStruct)
	if ret != 0 || err != nil {
		return fmt.Errorf("Unable to update element for map with file descriptor %d: %s", fd, err)
	}
	return nil
}
