// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package dataapi

import "github.com/cilium/tetragon/pkg/api/processapi"

type DataEventID struct {
	Pid  uint64
	Time uint64
}

type DataEventDesc struct {
	Error    int32
	Pad      uint32
	Leftover uint32
	Size     uint32
	ID       DataEventID
}

type MsgData struct {
	Common processapi.MsgCommon
	ID     DataEventID
}
