//go:build windows

package bpf

import (
	"github.com/cilium/ebpf"
)

var (
	execColl *ebpf.Collection
)

func SetExecCollection(coll *ebpf.Collection) {
	execColl = coll
}

func GetExecCollection() *ebpf.Collection {
	return execColl
}
