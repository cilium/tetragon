// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"fmt"
	"io"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/syscallinfo"
)

// EventEncoder is an interface for encoding tetragon.GetEventsResponse.
type EventEncoder interface {
	Encode(v interface{}) error
}

// ColorMode defines color mode flags for compact output.
type ColorMode string

const (
	Always ColorMode = "always" // always enable colored output.
	Never  ColorMode = "never"  // disable colored output.
	Auto   ColorMode = "auto"   // automatically enable / disable colored output based on terminal settings.
)

// CompactEncoder encodes tetragon.GetEventsResponse in a short format with emojis and colors.
type CompactEncoder struct {
	writer  io.Writer
	colorer *colorer
}

// NewCompactEncoder initializes and returns a pointer to CompactEncoder.
func NewCompactEncoder(w io.Writer, colorMode ColorMode) *CompactEncoder {
	return &CompactEncoder{
		writer:  w,
		colorer: newColorer(colorMode),
	}
}

// Encode implements EventEncoder.Encode.
func (p *CompactEncoder) Encode(v interface{}) error {
	event, ok := v.(*tetragon.GetEventsResponse)
	if !ok {
		return fmt.Errorf("invalid event")
	}
	logger.GetLogger().WithField("event", v).Debug("Processing event")
	str, err := p.eventToString(event)
	if err != nil {
		return err
	}
	fmt.Fprintln(p.writer, str)
	return nil
}

const (
	capsPad = 120
)

func capTrailorPrinter(str string, caps string) string {
	if len(caps) == 0 {
		return fmt.Sprintf("%s", str)
	}
	padding := 0
	if len(str) < capsPad {
		padding = capsPad - len(str)
	}
	return fmt.Sprintf("%s %*s", str, padding, caps)
}

var (
	CLONE_NEWCGROUP = 0x2000000
	CLONE_NEWIPC    = 0x8000000
	CLONE_NEWNET    = 0x40000000
	CLONE_NEWNS     = 0x20000
	CLONE_NEWPID    = 0x20000000
	CLONE_NEWTIME   = 0x80
	CLONE_NEWUSER   = 0x10000000
	CLONE_NEWUTS    = 0x4000000
)

var nsId = map[int32]string{
	int32(0):               "any",
	int32(CLONE_NEWCGROUP): "cgroup",
	int32(CLONE_NEWIPC):    "ipc",
	int32(CLONE_NEWNET):    "net",
	int32(CLONE_NEWNS):     "mnt",
	int32(CLONE_NEWPID):    "pid",
	int32(CLONE_NEWTIME):   "time",
	int32(CLONE_NEWUSER):   "user",
	int32(CLONE_NEWUTS):    "uts",
}

func printNS(ns int32) string {
	return nsId[ns]
}

func (p *CompactEncoder) eventToString(response *tetragon.GetEventsResponse) (string, error) {
	switch response.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		exec := response.GetProcessExec()
		if exec.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🚀 %-7s", "process")
		processInfo, caps := p.colorer.processInfo(response.NodeName, exec.Process)
		args := p.colorer.cyan.Sprint(exec.Process.Arguments)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, args), caps), nil
	case *tetragon.GetEventsResponse_ProcessExit:
		exit := response.GetProcessExit()
		if exit.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("💥 %-7s", "exit")
		processInfo, caps := p.colorer.processInfo(response.NodeName, exit.Process)
		args := p.colorer.cyan.Sprint(exit.Process.Arguments)
		var status string
		if exit.Signal != "" {
			status = p.colorer.red.Sprint(exit.Signal)
		} else {
			status = p.colorer.red.Sprint(exit.Status)
		}
		return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, args, status), caps), nil
	case *tetragon.GetEventsResponse_ProcessKprobe:
		kprobe := response.GetProcessKprobe()
		if kprobe.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		processInfo, caps := p.colorer.processInfo(response.NodeName, kprobe.Process)
		switch kprobe.FunctionName {
		case "__x64_sys_write":
			event := p.colorer.blue.Sprintf("📝 %-7s", "write")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = p.colorer.cyan.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "__x64_sys_read":
			event := p.colorer.blue.Sprintf("📚 %-7s", "read")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = p.colorer.cyan.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "fd_install":
			event := p.colorer.blue.Sprintf("📬 %-7s", "open")
			file := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil && kprobe.Args[1].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[1].GetFileArg().Path)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "__x64_sys_close":
			event := p.colorer.blue.Sprintf("📪 %-7s", "close")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "__x64_sys_mount":
			event := p.colorer.blue.Sprintf("💾 %-7s", "mount")
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = p.colorer.cyan.Sprint(kprobe.Args[0].GetStringArg())
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = p.colorer.cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "__x64_sys_setuid":
			event := p.colorer.blue.Sprintf("🔑 %-7s", "setuid")
			uid := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				uidInt := p.colorer.cyan.Sprint(kprobe.Args[0].GetIntArg())
				uid = string(uidInt)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, uid), caps), nil
		case "__x64_sys_clock_settime":
			event := p.colorer.blue.Sprintf("⏰ %-7s", "clock_settime")
			return capTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "__x64_sys_pivot_root":
			event := p.colorer.blue.Sprintf("💾 %-7s", "pivot_root")
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = p.colorer.cyan.Sprint(kprobe.Args[0].GetStringArg())
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = p.colorer.cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "proc_exec_connector":
			event := p.colorer.blue.Sprintf("🔧 %-7s", "proc_exec_connector")
			return capTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "__x64_sys_setns":
			netns := ""
			event := p.colorer.blue.Sprintf("🔧 %-7s", "setns")
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				netns = printNS(kprobe.Args[1].GetIntArg())
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, netns), caps), nil
		case "tcp_connect":
			event := p.colorer.blue.Sprintf("🔌 %-7s", "connect")
			sock := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				sock = p.colorer.cyan.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sock), caps), nil
		case "tcp_close":
			event := p.colorer.blue.Sprintf("\U0001F9F9 %-7s", "close")
			sock := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				sock = p.colorer.cyan.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sock), caps), nil
		case "tcp_sendmsg":
			event := p.colorer.blue.Sprintf("📤 %-7s", "sendmsg")
			args := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				args = p.colorer.cyan.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			bytes := int32(0)
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				bytes = kprobe.Args[1].GetIntArg()
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s bytes %d", event, processInfo, args, bytes), caps), nil
		default:
			event := p.colorer.blue.Sprintf("⁉️ %-7s", "syscall")
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, kprobe.FunctionName), caps), nil
		}
	case *tetragon.GetEventsResponse_ProcessDns:
		dns := response.GetProcessDns()
		if dns.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		if dns.Dns == nil {
			return "", fmt.Errorf("dns field is not set")
		}
		event := p.colorer.blue.Sprintf("📖 %-7s", "dns")
		processInfo, caps := p.colorer.processInfo(response.NodeName, dns.Process)
		args := p.colorer.cyan.Sprint(dns.GetDns().Names, " => ", dns.GetDns().Ips)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, args), caps), nil
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		tp := response.GetProcessTracepoint()
		if tp.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		processInfo, caps := p.colorer.processInfo(response.NodeName, tp.Process)
		switch fmt.Sprintf("%s/%s", tp.Subsys, tp.Event) {
		case "raw_syscalls/sys_enter":
			event := p.colorer.blue.Sprintf("☎  %-7s", "syscall")
			sysName := rawSyscallEnter(p, tp)
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sysName), caps), nil
		default:
			event := p.colorer.blue.Sprintf("⁉️ %-7s", "tracepoint")
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, tp.Subsys, tp.Event), caps), nil
		}
	}

	return "", fmt.Errorf("unknown event type")
}

func rawSyscallEnter(p *CompactEncoder, tp *tetragon.ProcessTracepoint) string {
	sysID := int64(-1)
	if len(tp.Args) > 0 && tp.Args[0] != nil {
		if x, ok := tp.Args[0].GetArg().(*tetragon.KprobeArgument_LongArg); ok {
			sysID = x.LongArg
		}
	}
	sysName := "unknown"
	if name := syscallinfo.GetSyscallName(int(sysID)); name != "" {
		sysName = name
		sysArgs, ok := syscallinfo.GetSyscallArgs(sysName)
		if ok {
			sysName += "("
			for j, arg := range sysArgs {
				if j > 0 {
					sysName += ", "
				}
				i := j + 1

				argVal := "?"
				isPtr := false
				if len(tp.Args) > i && tp.Args[i] != nil {
					if x, ok := tp.Args[i].GetArg().(*tetragon.KprobeArgument_SizeArg); ok {
						argVal_ := x.SizeArg
						if len(arg.Type) > 0 && arg.Type[len(arg.Type)-1] == '*' {
							isPtr = true
							argVal = fmt.Sprintf("0x%x", argVal_)
						} else {
							argVal = fmt.Sprintf("%d", argVal_)
						}
					}
				}
				if isPtr {
					sysName += fmt.Sprintf("%s%s=%s", arg.Type, arg.Name, argVal)
				} else {
					sysName += fmt.Sprintf("%s %s=%s", arg.Type, arg.Name, argVal)
				}
			}
			sysName += ")"
		}
	}
	return sysName
}
