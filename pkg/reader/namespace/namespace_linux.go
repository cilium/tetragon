// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package namespace

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

type hostNamespaces struct {
	ns  *tetragon.Namespaces
	err error
}

var (
	// listNamespaces is the order how we read namespaces from /proc
	listNamespaces = [10]string{"uts", "ipc", "mnt", "pid", "pid_for_children", "net", "time", "time_for_children", "cgroup", "user"}

	hostNs     hostNamespaces
	hostNsOnce sync.Once

	// If kernel supports time namespace
	TimeNsSupport bool
)

// GetPidNsInode() returns the inode of the target namespace pointed by pid.
// Returns:
//
//	namespace inode and nil on success
//	0 and error on failures.
func GetPidNsInode(pid uint32, nsStr string) (uint32, error) {
	pidStr := strconv.Itoa(int(pid))
	netns := filepath.Join(option.Config.ProcFS, pidStr, "ns", nsStr)
	netStr, err := os.Readlink(netns)
	if err != nil {
		return 0, fmt.Errorf("namespace '%s' %v", netns, err)
	}
	fields := strings.Split(netStr, ":")
	if len(fields) < 2 {
		return 0, fmt.Errorf("parsing namespace '%s' fields", netns)
	}
	inode := fields[1]
	inode = strings.TrimRight(inode, "]")
	inode = strings.TrimLeft(inode, "[")
	inodeEntry, _ := strconv.ParseUint(inode, 10, 32)
	return uint32(inodeEntry), nil
}

func GetMyPidG() uint32 {
	selfBinary := filepath.Base(os.Args[0])
	if procfs := os.Getenv("TETRAGON_PROCFS"); procfs != "" {
		procFS, _ := os.ReadDir(procfs)
		for _, d := range procFS {
			if !d.IsDir() {
				continue
			}
			cmdline, err := os.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
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

func GetHostNsInode(nsStr string) (uint32, error) {
	return GetPidNsInode(1, nsStr)
}

func GetSelfNsInode(nsStr string) (uint32, error) {
	return GetPidNsInode(uint32(GetMyPidG()), nsStr)
}

func GetCurrentNamespace() *tetragon.Namespaces {
	hostNs, err := InitHostNamespace()
	if err != nil {
		return nil
	}
	self_ns := make(map[string]uint32)
	for i := 0; i < len(listNamespaces); i++ {
		ino, err := GetSelfNsInode(listNamespaces[i])
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Failed to read current namespace")
			continue
		}
		self_ns[listNamespaces[i]] = ino
	}

	retVal := &tetragon.Namespaces{
		Uts: &tetragon.Namespace{
			Inum:   self_ns["uts"],
			IsHost: hostNs.Uts.Inum == self_ns["uts"],
		},
		Ipc: &tetragon.Namespace{
			Inum:   self_ns["ipc"],
			IsHost: hostNs.Ipc.Inum == self_ns["ipc"],
		},
		Mnt: &tetragon.Namespace{
			Inum:   self_ns["mnt"],
			IsHost: hostNs.Mnt.Inum == self_ns["mnt"],
		},
		Pid: &tetragon.Namespace{
			Inum:   self_ns["pid"],
			IsHost: hostNs.Pid.Inum == self_ns["pid"],
		},
		PidForChildren: &tetragon.Namespace{
			Inum:   self_ns["pid_for_children"],
			IsHost: hostNs.PidForChildren.Inum == self_ns["pid_for_children"],
		},
		Net: &tetragon.Namespace{
			Inum:   self_ns["net"],
			IsHost: hostNs.Net.Inum == self_ns["net"],
		},
		Time: &tetragon.Namespace{
			Inum: self_ns["time"],
			// Check first if this kernel supports time namespace
			IsHost: hostNs.Time.Inum != 0 && hostNs.Time.Inum == self_ns["time"],
		},
		TimeForChildren: &tetragon.Namespace{
			Inum: self_ns["time_for_children"],
			// Check first if this kernel supports time namespace
			IsHost: hostNs.TimeForChildren.Inum != 0 && hostNs.TimeForChildren.Inum == self_ns["time_for_children"],
		},
		Cgroup: &tetragon.Namespace{
			Inum:   self_ns["cgroup"],
			IsHost: hostNs.Cgroup.Inum == self_ns["cgroup"],
		},
		User: &tetragon.Namespace{
			Inum:   self_ns["user"],
			IsHost: hostNs.User.Inum == self_ns["user"],
		},
	}

	// This kernel does not support time namespace, so we explicitly set them to nil
	if retVal.Time.Inum == 0 {
		retVal.Time = nil
		retVal.TimeForChildren = nil
	}

	return retVal
}

func IsMsgNsInHostMntUser(ns *processapi.MsgNamespaces) (bool, error) {
	hostNs, err := InitHostNamespace()
	if err != nil {
		return false, err
	}

	if ns.MntInum == hostNs.Mnt.Inum && ns.UserInum == hostNs.User.Inum {
		return true, nil
	}

	return false, nil
}

func GetMsgNamespaces(ns processapi.MsgNamespaces) (*tetragon.Namespaces, error) {
	hostNs, err := InitHostNamespace()
	if err != nil {
		return nil, err
	}
	retVal := &tetragon.Namespaces{
		Uts: &tetragon.Namespace{
			Inum:   ns.UtsInum,
			IsHost: hostNs.Uts.Inum == ns.UtsInum,
		},
		Ipc: &tetragon.Namespace{
			Inum:   ns.IpcInum,
			IsHost: hostNs.Ipc.Inum == ns.IpcInum,
		},
		Mnt: &tetragon.Namespace{
			Inum:   ns.MntInum,
			IsHost: hostNs.Mnt.Inum == ns.MntInum,
		},
		Pid: &tetragon.Namespace{
			Inum:   ns.PidInum,
			IsHost: hostNs.Pid.Inum == ns.PidInum,
		},
		PidForChildren: &tetragon.Namespace{
			Inum:   ns.PidChildInum,
			IsHost: hostNs.PidForChildren.Inum == ns.PidChildInum,
		},
		Net: &tetragon.Namespace{
			Inum:   ns.NetInum,
			IsHost: hostNs.Net.Inum == ns.NetInum,
		},
		Time: &tetragon.Namespace{
			Inum: ns.TimeInum,
			// Check first if this kernel supports time namespace
			IsHost: hostNs.Time.Inum != 0 && hostNs.Time.Inum == ns.TimeInum,
		},
		TimeForChildren: &tetragon.Namespace{
			Inum: ns.TimeChildInum,
			// Check first if this kernel supports time namespace
			IsHost: hostNs.TimeForChildren.Inum != 0 && hostNs.TimeForChildren.Inum == ns.TimeChildInum,
		},
		Cgroup: &tetragon.Namespace{
			Inum:   ns.CgroupInum,
			IsHost: hostNs.Cgroup.Inum == ns.CgroupInum,
		},
		User: &tetragon.Namespace{
			Inum:   ns.UserInum,
			IsHost: hostNs.User.Inum == ns.UserInum,
		},
	}

	// This kernel does not support time namespace, so we explicitly set them to nil
	if retVal.Time.Inum == 0 {
		retVal.Time = nil
		retVal.TimeForChildren = nil
	}

	return retVal, nil
}

func initHostNamespace() (*tetragon.Namespaces, error) {
	_, err := os.Stat(filepath.Join(option.Config.ProcFS, "1", "ns", "time"))
	if err != nil {
		logger.GetLogger().WithError(err).Infof("Kernel does not support time namespaces")
	} else {
		TimeNsSupport = true
	}

	knownNamespaces := make(map[string]*tetragon.Namespace)
	for _, n := range listNamespaces {
		ino, err := GetPidNsInode(1, n)
		if err != nil {
			if (n == "time" || n == "time_for_children") && !TimeNsSupport {
				// Explicitly initialize host time namespace to zero which indicates
				// kernel does not support it.
				knownNamespaces[n] = &tetragon.Namespace{Inum: 0, IsHost: false}
				continue
			}
			return nil, err
		}
		// Ino can't be zero here
		knownNamespaces[n] = &tetragon.Namespace{
			Inum:   ino,
			IsHost: true,
		}
	}

	return &tetragon.Namespaces{
		Uts:             knownNamespaces["uts"],
		Ipc:             knownNamespaces["ipc"],
		Mnt:             knownNamespaces["mnt"],
		Pid:             knownNamespaces["pid"],
		PidForChildren:  knownNamespaces["pid_for_children"],
		Net:             knownNamespaces["net"],
		Time:            knownNamespaces["time"],
		TimeForChildren: knownNamespaces["time_for_children"],
		Cgroup:          knownNamespaces["cgroup"],
		User:            knownNamespaces["user"],
	}, nil
}

// InitHostNamespace() Initialize host namespaces.
//
// This function is explicitly inside a once.Do() as we have to
// initialize host namespaces only once, no need to access /proc/1/
// multiple times.
//
// Returns:
//
//	Host namespaces as a tetragon.Namespaces object on success
//	Nil and an error on failure
func InitHostNamespace() (*tetragon.Namespaces, error) {
	hostNsOnce.Do(func() {
		hostNs.ns, hostNs.err = initHostNamespace()
	})

	return hostNs.ns, hostNs.err
}
