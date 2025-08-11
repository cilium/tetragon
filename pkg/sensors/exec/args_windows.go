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
	cmd_map   *ebpf.Map
	image_map *ebpf.Map
)

func getArgsFromPID(PID uint32) (string, string, error) {

	if (cmd_map == nil) || (image_map == nil) {
		coll, _ := bpf.GetCollection("ProcessMonitor")
		if coll == nil {
			return "", "", errors.New("exec Preloaded collection is nil")
		}
		var ok bool
		cmd_map, ok = coll.Maps["command_map"]
		if !ok {
			return "", "", errors.New("commad_map not found or not pinned")
		}
		image_map, ok = coll.Maps["process_map"]
		if !ok {
			return "", "", errors.New("commad_map not found or not pinned")
		}
	}
	var wideCmd [2048]uint16
	err := cmd_map.Lookup(PID, &wideCmd)
	if err == nil {
		cmd_map.Delete(PID)
	}
	strCmd := windows.UTF16ToString(wideCmd[:])

	var wideImagePath [1024]byte
	err = image_map.Lookup(PID, &wideImagePath)
	if err == nil {
		image_map.Delete(PID)
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
