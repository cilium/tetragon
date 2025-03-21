// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package namespace

import (
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

type hostNamespaces struct {
	ns  *tetragon.Namespaces
	err error
}

func GetMyPidG() uint32 {
	return uint32(os.Getpid())
}

func IsMsgNsInHostMntUser(ns *processapi.MsgNamespaces) (bool, error) {
	return true, nil
}

func getConstNamespaces() (*tetragon.Namespaces, error) {
	retVal := &tetragon.Namespaces{
		Uts: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Ipc: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Mnt: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Pid: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		PidForChildren: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Net: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Time: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		TimeForChildren: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Cgroup: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		User: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
	}

	retVal.Time = nil
	retVal.TimeForChildren = nil

	return retVal, nil
}
func GetMsgNamespaces(ns processapi.MsgNamespaces) (*tetragon.Namespaces, error) {
	return getConstNamespaces()
}
