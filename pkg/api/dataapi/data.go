package dataapi

import "github.com/cilium/tetragon/pkg/api/processapi"

type DataEventId struct {
	Pid  uint64
	Time uint64
}

type DataEventDesc struct {
	Error    int32
	Pad      uint32
	Leftover uint32
	Size     uint32
	Id       DataEventId
}

type MsgData struct {
	Common processapi.MsgCommon
	Id     DataEventId
}
