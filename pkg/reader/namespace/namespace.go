// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package namespace

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/isovalent/tetragon-oss/api/v1/fgs"
	"github.com/isovalent/tetragon-oss/pkg/api/processapi"
	"github.com/isovalent/tetragon-oss/pkg/logger"
	"github.com/isovalent/tetragon-oss/pkg/option"
)

var hostNamespace *fgs.Namespaces

func GetPidNsInode(pid uint32, nsStr string) uint32 {
	pidStr := strconv.Itoa(int(pid))
	netns := filepath.Join(option.Config.ProcFS, pidStr, "ns", nsStr)
	netStr, err := os.Readlink(netns)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("GetPidNsInode")
		return 0
	}
	fields := strings.Split(netStr, ":")
	if len(fields) < 2 {
		logger.GetLogger().Errorf("GetPidNsInode: Error cannot parse %s\n", netStr)
		return 0
	}
	inode := fields[1]
	inode = strings.TrimRight(inode, "]")
	inode = strings.TrimLeft(inode, "[")
	inodeEntry, _ := strconv.ParseUint(inode, 10, 32)
	return uint32(inodeEntry)
}

func GetMyPidG() uint32 {
	selfBinary := filepath.Base(os.Args[0])
	if procfs := os.Getenv("FGS_PROCFS"); procfs != "" {
		procFS, _ := ioutil.ReadDir(procfs)
		for _, d := range procFS {
			if d.IsDir() == false {
				continue
			}
			cmdline, err := ioutil.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
			if err != nil {
				continue
			}
			if strings.Contains(string(cmdline), selfBinary) {
				pid, err := strconv.ParseUint(d.Name(), 10, 32)
				if err != nil {
					continue
				}
				return uint32(pid)
			}
		}
	}
	return uint32(os.Getpid())
}

func GetHostNsInode(nsStr string) uint32 {
	return GetPidNsInode(1, nsStr)
}

func GetSelfNsInode(nsStr string) uint32 {
	return GetPidNsInode(uint32(GetMyPidG()), nsStr)
}

func GetCurrentNamespace() *fgs.Namespaces {
	nses := [10]string{"uts", "ipc", "mnt", "pid", "pid_for_children", "net", "time", "time_for_children", "cgroup", "user"}
	self_ns := make(map[string]uint32)
	is_root_ns := make(map[string]bool)
	for i := 0; i < len(nses); i++ {
		self_ns[nses[i]] = GetSelfNsInode(nses[i])
		is_root_ns[nses[i]] = (self_ns[nses[i]] == GetHostNsInode(nses[i]))
	}

	return &fgs.Namespaces{
		Uts: &fgs.Namespace{
			Inum:   self_ns["uts"],
			IsHost: is_root_ns["uts"],
		},
		Ipc: &fgs.Namespace{
			Inum:   self_ns["ipc"],
			IsHost: is_root_ns["ipc"],
		},
		Mnt: &fgs.Namespace{
			Inum:   self_ns["mnt"],
			IsHost: is_root_ns["mnt"],
		},
		Pid: &fgs.Namespace{
			Inum:   self_ns["pid"],
			IsHost: is_root_ns["pid"],
		},
		PidForChildren: &fgs.Namespace{
			Inum:   self_ns["pid_for_children"],
			IsHost: is_root_ns["pid_for_children"],
		},
		Net: &fgs.Namespace{
			Inum:   self_ns["net"],
			IsHost: is_root_ns["net"],
		},
		Time: &fgs.Namespace{
			Inum:   self_ns["time"],
			IsHost: is_root_ns["time"],
		},
		TimeForChildren: &fgs.Namespace{
			Inum:   self_ns["time_for_children"],
			IsHost: is_root_ns["time_for_children"],
		},
		Cgroup: &fgs.Namespace{
			Inum:   self_ns["cgroup"],
			IsHost: is_root_ns["cgroup"],
		},
		User: &fgs.Namespace{
			Inum:   self_ns["user"],
			IsHost: is_root_ns["user"],
		},
	}
}
func GetMsgNamespaces(ns processapi.MsgNamespaces) *fgs.Namespaces {
	hostNs := GetHostNamespace()
	retVal := &fgs.Namespaces{
		Uts: &fgs.Namespace{
			Inum:   ns.UtsInum,
			IsHost: hostNs.Uts.Inum == ns.UtsInum,
		},
		Ipc: &fgs.Namespace{
			Inum:   ns.IpcInum,
			IsHost: hostNs.Ipc.Inum == ns.IpcInum,
		},
		Mnt: &fgs.Namespace{
			Inum:   ns.MntInum,
			IsHost: hostNs.Mnt.Inum == ns.MntInum,
		},
		Pid: &fgs.Namespace{
			Inum:   ns.PidInum,
			IsHost: hostNs.Pid.Inum == ns.PidInum,
		},
		PidForChildren: &fgs.Namespace{
			Inum:   ns.PidChildInum,
			IsHost: hostNs.PidForChildren.Inum == ns.PidChildInum,
		},
		Net: &fgs.Namespace{
			Inum:   ns.NetInum,
			IsHost: hostNs.Net.Inum == ns.NetInum,
		},
		Time: &fgs.Namespace{
			Inum:   ns.TimeInum,
			IsHost: hostNs.Time.Inum == ns.TimeInum,
		},
		TimeForChildren: &fgs.Namespace{
			Inum:   ns.TimeChildInum,
			IsHost: hostNs.TimeForChildren.Inum == ns.TimeChildInum,
		},
		Cgroup: &fgs.Namespace{
			Inum:   ns.CgroupInum,
			IsHost: hostNs.Cgroup.Inum == ns.CgroupInum,
		},
		User: &fgs.Namespace{
			Inum:   ns.UserInum,
			IsHost: hostNs.User.Inum == ns.UserInum,
		},
	}

	// this kernel does not support time namespace
	if retVal.Time.Inum == 0 {
		retVal.Time = nil
		retVal.TimeForChildren = nil
	}

	return retVal
}

func GetHostNamespace() *fgs.Namespaces {
	if hostNamespace == nil {
		hostNamespace = &fgs.Namespaces{
			Uts:             createHostNs("uts"),
			Ipc:             createHostNs("ipc"),
			Mnt:             createHostNs("mnt"),
			Pid:             createHostNs("pid"),
			PidForChildren:  createHostNs("pid_for_children"),
			Net:             createHostNs("net"),
			Time:            createHostNs("time"),
			TimeForChildren: createHostNs("time_for_children"),
			Cgroup:          createHostNs("cgroup"),
			User:            createHostNs("user"),
		}
	}
	return hostNamespace
}

func createHostNs(ns string) *fgs.Namespace {
	return &fgs.Namespace{
		Inum:   GetPidNsInode(1, ns),
		IsHost: true,
	}
}
