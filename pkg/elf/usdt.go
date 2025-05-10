// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

type UsdtArgType int

const (
	USDT_ARG_TYPE_NONE      uint8 = 0
	USDT_ARG_TYPE_CONST     uint8 = 1
	USDT_ARG_TYPE_REG       uint8 = 2
	USDT_ARG_TYPE_REG_DEREF uint8 = 3
)

type UsdtArg struct {
	ValOff uint64
	RegOff uint16
	Shift  uint8
	Type   uint8
	Signed bool
	Size   int
	Str    string
}

type UsdtSpec struct {
	Off      uint64
	Base     uint64
	Sema     uint64
	Provider string
	Name     string
	ArgsStr  string
	ArgsCnt  uint32
	Args     [12]UsdtArg
}

type UsdtTarget struct {
	Spec    *UsdtSpec
	IpAbs   uint64
	IpRel   uint64
	SemaOff uint64
}
