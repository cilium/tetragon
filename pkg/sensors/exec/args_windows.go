// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"errors"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/windows"

	"github.com/cilium/tetragon/pkg/bpf"
)

var (
	cmdMap   *ebpf.Map
	imageMap *ebpf.Map
)

func getArgsFromPID(PID uint32) (string, string, error) {

	if (cmdMap == nil) || (imageMap == nil) {
		coll, _ := bpf.GetCollection("ProcessMonitor")
		if coll == nil {
			return "", "", errors.New("exec Preloaded collection is nil")
		}
		var ok bool
		cmdMap, ok = coll.Maps["command_map"]
		if !ok {
			return "", "", errors.New("commad_map not found or not pinned")
		}
		imageMap, ok = coll.Maps["process_map"]
		if !ok {
			return "", "", errors.New("commad_map not found or not pinned")
		}
	}
	var wideCmd [2048]uint16
	err := cmdMap.Lookup(PID, &wideCmd)
	if err == nil {
		cmdMap.Delete(PID)
	}
	strCmd := windows.UTF16ToString(wideCmd[:])

	var wideImagePath [1024]byte
	err = imageMap.Lookup(PID, &wideImagePath)
	if err == nil {
		imageMap.Delete(PID)
	}
	var s = (*uint16)(unsafe.Pointer(&wideImagePath[0]))
	strImagePath := windows.UTF16PtrToString(s)

	strImagePath = strings.TrimPrefix(strImagePath, "\\??\\")
	stringToTrim := strImagePath

	if strings.HasPrefix(strCmd, "\"") {
		stringToTrim = "\"" + stringToTrim + "\""
	}
	strCmd = strings.TrimPrefix(strCmd, stringToTrim)
	strCmd = strings.TrimPrefix(strCmd, " ")
	return strImagePath, strCmd, nil

}
