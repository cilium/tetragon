// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/logger"

	"google.golang.org/protobuf/encoding/protojson"
)

const rfc3339Nano = "2006-01-02T15:04:05.000000000Z07:00"

var (
	ErrInvalidEvent       = errors.New("invalid event")
	ErrMissingProcessInfo = errors.New("process field is not set")
	ErrUnknownEventType   = errors.New("unknown event type")
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

type TtyEncoder struct {
	Writer io.Writer
	Tty    string
}

func NewTtyEncoder(w io.Writer, tty string) *TtyEncoder {
	return &TtyEncoder{
		Writer: w,
		Tty:    tty,
	}
}

// Encode implements EventEncoder.Encode.
func (p *TtyEncoder) Encode(v interface{}) error {
	event, ok := v.(*tetragon.GetEventsResponse)
	if !ok {
		return ErrInvalidEvent
	}

	switch event.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessKprobe:
		kprobe := event.GetProcessKprobe()

		file := ""
		if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
			file = kprobe.Args[0].GetFileArg().Path
		}

		if file != p.Tty {
			return nil
		}

		bytes := []byte{}
		if len(kprobe.Args) > 1 && kprobe.Args[1] != nil && kprobe.Args[1].GetBytesArg() != nil {
			bytes = kprobe.Args[1].GetBytesArg()
		}

		os.Stdout.Write(bytes)
	}
	return nil
}

// CompactEncoder encodes tetragon.GetEventsResponse in a short format with emojis and colors.
type CompactEncoder struct {
	Writer      io.Writer
	Colorer     *Colorer
	Timestamps  bool
	StackTraces bool
	ImaHash     bool
}

// NewCompactEncoder initializes and returns a pointer to CompactEncoder.
func NewCompactEncoder(w io.Writer, colorMode ColorMode, timestamps bool, stackTraces bool, imaHash bool) *CompactEncoder {
	return &CompactEncoder{
		Writer:      w,
		Colorer:     NewColorer(colorMode),
		Timestamps:  timestamps,
		StackTraces: stackTraces,
		ImaHash:     imaHash,
	}
}

// Encode implements EventEncoder.Encode.
func (p *CompactEncoder) Encode(v interface{}) error {
	event, ok := v.(*tetragon.GetEventsResponse)
	if !ok {
		return ErrInvalidEvent
	}
	logger.GetLogger().With("event", v).Debug("Processing event")
	str, err := p.EventToString(event)
	if err != nil {
		return err
	}
	if p.Timestamps {
		ts := event.Time.AsTime().UTC().Format(rfc3339Nano)
		str = fmt.Sprintf("%s %s", ts, str)
	}
	fmt.Fprintln(p.Writer, str)

	// print stack trace if available
	if p.StackTraces {
		st := HumanStackTrace(event, p.Colorer)
		fmt.Fprint(p.Writer, st)
	}

	// print ima hash if available
	if p.ImaHash {
		st := HumanIMAHash(event, p.Colorer)
		fmt.Fprint(p.Writer, st)
	}

	return nil
}

type ProtojsonEncoder struct {
	w io.Writer
}

func NewProtojsonEncoder(w io.Writer) *ProtojsonEncoder {
	return &ProtojsonEncoder{
		w,
	}
}

func (p *ProtojsonEncoder) Encode(v interface{}) error {
	// TODO(WF): We may want to implement a streaming API here, similar to what they do in
	// encoding/json. For now, I think this is probably fine though.
	event, ok := v.(*tetragon.GetEventsResponse)
	if !ok {
		return ErrInvalidEvent
	}
	out, err := protojson.MarshalOptions{
		// Our old exporter's behaviour was to use the snake_case names rather than
		// camelCase. We want to maintain backward compatibility here so let's do the
		// same thing in the protojson encoder.
		UseProtoNames: true,
	}.Marshal(event)
	if err != nil {
		return err
	}
	fmt.Fprintln(p.w, string(out))
	return nil
}

const (
	capsPad = 120
)

func CapTrailorPrinter(str string, caps string) string {
	if len(caps) == 0 {
		return str
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

func PrintNS(ns int32) string {
	return nsId[ns]
}

func HumanStackTrace(response *tetragon.GetEventsResponse, colorer *Colorer) string {
	out := new(strings.Builder)
	if ev, ok := response.Event.(*tetragon.GetEventsResponse_ProcessKprobe); ok {
		if ev.ProcessKprobe.KernelStackTrace != nil {
			fmt.Fprintf(out, "Kernel:\n")
			for _, st := range ev.ProcessKprobe.KernelStackTrace {
				colorer.Green.Fprintf(out, "   0x%x:", st.Address)
				colorer.Blue.Fprintf(out, " %s", st.Symbol)
				fmt.Fprintf(out, "+")
				colorer.Yellow.Fprintf(out, "0x%x\n", st.Offset)
			}
		}
		if ev.ProcessKprobe.UserStackTrace != nil {
			fmt.Fprintf(out, "User:\n")
			for _, st := range ev.ProcessKprobe.UserStackTrace {
				colorer.Green.Fprintf(out, "   0x%x:", st.Address)
				if st.Symbol != "" {
					colorer.Blue.Fprintf(out, " %s", st.Symbol)
				}
				colorer.Yellow.Fprintf(out, " (%s+0x%x)\n", st.Module, st.Offset)
			}
		}
	}
	return out.String()
}
func HumanIMAHash(response *tetragon.GetEventsResponse, colorer *Colorer) string {
	out := new(strings.Builder)
	if ev, ok := response.Event.(*tetragon.GetEventsResponse_ProcessLsm); ok {
		if ev.ProcessLsm.ImaHash != "" {
			var path string
			switch ev.ProcessLsm.FunctionName {
			case "bprm_check_security":
				fallthrough
			case "bprm_committed_creds":
				fallthrough
			case "bprm_committing_creds":
				fallthrough
			case "bprm_creds_for_exec":
				fallthrough
			case "bprm_creds_from_file":
				path = ev.ProcessLsm.Args[0].GetLinuxBinprmArg().Path
			case "file_ioctl":
				fallthrough
			case "file_lock":
				fallthrough
			case "file_open":
				fallthrough
			case "file_post_open":
				fallthrough
			case "file_receive":
				fallthrough
			case "mmap_file":
				path = ev.ProcessLsm.Args[0].GetFileArg().Path
			default:
			}
			if path != "" {
				colorer.Green.Fprintf(out, "   %s", path)
				colorer.Blue.Fprintf(out, " %s\n", ev.ProcessLsm.ImaHash)
			}
		}
	}
	return out.String()
}

func (p *CompactEncoder) EventToString(response *tetragon.GetEventsResponse) (string, error) {
	switch response.Event.(type) {
	case *tetragon.GetEventsResponse_Test:
		// This shouldn't normally be reachable since Tetragon won't generate Test
		// events outside of specific unit tests.
		return "TEST EVENT", nil
	case *tetragon.GetEventsResponse_ProcessExec:
		exec := response.GetProcessExec()
		if exec.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.Colorer.Blue.Sprintf("🚀 %-7s", "process")
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, exec.Process)
		args := p.Colorer.Cyan.Sprint(exec.Process.Arguments)
		return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, args), caps), nil
	case *tetragon.GetEventsResponse_ProcessExit:
		exit := response.GetProcessExit()
		if exit.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.Colorer.Blue.Sprintf("💥 %-7s", "exit")
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, exit.Process)
		args := p.Colorer.Cyan.Sprint(exit.Process.Arguments)
		var status string
		if exit.Signal != "" {
			status = p.Colorer.Red.Sprint(exit.Signal)
		} else {
			status = p.Colorer.Red.Sprint(exit.Status)
		}
		return CapTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, args, status), caps), nil
	case *tetragon.GetEventsResponse_ProcessThrottle:
		throttle := response.GetProcessThrottle()
		event := p.Colorer.Red.Sprintf("🧬 %-7s", "throttle")
		var typ string
		switch throttle.Type {
		case tetragon.ThrottleType_THROTTLE_START:
			typ = p.Colorer.Red.Sprint("START")
		case tetragon.ThrottleType_THROTTLE_STOP:
			typ = p.Colorer.Green.Sprint("STOP ")
		}
		return fmt.Sprintf("%s %s %s", event, typ, throttle.Cgroup), nil
	case *tetragon.GetEventsResponse_ProcessLoader:
		loader := response.GetProcessLoader()
		if loader.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.Colorer.Blue.Sprintf("🧬 %-7s", "loader")
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, loader.Process)
		var buildid string
		if len(loader.Buildid) > 0 {
			buildid = hex.EncodeToString(loader.Buildid) + " "
		}
		path := p.Colorer.Yellow.Sprint(loader.Path)
		return CapTrailorPrinter(fmt.Sprintf("%s %s %s%s", event, processInfo,
			buildid, path), caps), nil
	case *tetragon.GetEventsResponse_ProcessKprobe:
		kprobe := response.GetProcessKprobe()
		if kprobe.Process == nil {
			return "", ErrMissingProcessInfo
		}
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, kprobe.Process)
		_, sc := arch.CutSyscallPrefix(kprobe.FunctionName)
		switch sc {
		case "sys_write":
			event := p.Colorer.Blue.Sprintf("📝 %-7s", "write")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.Colorer.Cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = p.Colorer.Cyan.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "sys_read":
			event := p.Colorer.Blue.Sprintf("📚 %-7s", "read")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.Colorer.Cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = p.Colorer.Cyan.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "fd_install":
			event := p.Colorer.Blue.Sprintf("📬 %-7s", "open")
			file := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil && kprobe.Args[1].GetFileArg() != nil {
				file = p.Colorer.Cyan.Sprint(kprobe.Args[1].GetFileArg().Path)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "sys_openat":
			event := p.Colorer.Blue.Sprintf("📬️ %-7s", "openat")
			file := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				file = p.Colorer.Cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "sys_open":
			event := p.Colorer.Blue.Sprintf("📬️ %-7s", "open")
			file := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				file = p.Colorer.Cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "sys_close":
			event := p.Colorer.Blue.Sprintf("📪 %-7s", "close")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.Colorer.Cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "sys_mount":
			event := p.Colorer.Blue.Sprintf("💾 %-7s", "mount")
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = p.Colorer.Cyan.Sprint(kprobe.Args[0].GetStringArg())
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = p.Colorer.Cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "sys_setuid":
			event := p.Colorer.Blue.Sprintf("🔑 %-7s", "setuid")
			uid := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				uidInt := p.Colorer.Cyan.Sprint(kprobe.Args[0].GetIntArg())
				uid = string(uidInt)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, uid), caps), nil
		case "sys_clock_settime":
			event := p.Colorer.Blue.Sprintf("⏰ %-7s", "clock_settime")
			return CapTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "sys_pivot_root":
			event := p.Colorer.Blue.Sprintf("💾 %-7s", "pivot_root")
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = p.Colorer.Cyan.Sprint(kprobe.Args[0].GetStringArg())
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = p.Colorer.Cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "proc_exec_connector":
			event := p.Colorer.Blue.Sprintf("🔧 %-7s", "proc_exec_connector")
			return CapTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "sys_setns":
			netns := ""
			event := p.Colorer.Blue.Sprintf("🔧 %-7s", "setns")
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				netns = PrintNS(kprobe.Args[1].GetIntArg())
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, netns), caps), nil
		case "tcp_connect":
			event := p.Colorer.Blue.Sprintf("🔌 %-7s", "connect")
			sock := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				sock = p.Colorer.Cyan.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sock), caps), nil
		case "tcp_close":
			event := p.Colorer.Blue.Sprintf("\U0001F9F9 %-7s", "close")
			sock := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				sock = p.Colorer.Cyan.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sock), caps), nil
		case "tcp_sendmsg":
			event := p.Colorer.Blue.Sprintf("📤 %-7s", "sendmsg")
			args := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				args = p.Colorer.Cyan.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			bytes := int32(0)
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				bytes = kprobe.Args[1].GetIntArg()
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s bytes %d", event, processInfo, args, bytes), caps), nil
		case "bpf_check":
			event := p.Colorer.Blue.Sprintf("🐝 %-7s", "bpf_load")
			attr := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				ba := kprobe.Args[0].GetBpfAttrArg()
				attr = p.Colorer.Cyan.Sprintf("%s %s instruction count %d", ba.ProgType, ba.ProgName, ba.InsnCnt)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, attr), caps), nil
		case "security_perf_event_alloc":
			event := p.Colorer.Blue.Sprintf("🐝 %-7s", "perf_event_alloc")
			attr := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				p_event := kprobe.Args[0].GetPerfEventArg()
				attr = p.Colorer.Cyan.Sprintf("%s %s", p_event.Type, p_event.KprobeFunc)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, attr), caps), nil
		case "security_bpf_map_alloc":
			event := p.Colorer.Blue.Sprintf("🗺 %-7s", "bpf_map_create")
			attr := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				bpfmap := kprobe.Args[0].GetBpfMapArg()
				attr = p.Colorer.Cyan.Sprintf("%s %s key size %d value size %d max entries %d", bpfmap.MapType,
					bpfmap.MapName, bpfmap.KeySize, bpfmap.ValueSize, bpfmap.MaxEntries)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, attr), caps), nil
		case "security_file_permission":
			event := p.Colorer.Blue.Sprintf("❓ %-7s", "security_file_permission")
			attr := ""
			if len(kprobe.Args) > 1 && kprobe.Args[0] != nil && kprobe.Args[1] != nil {
				file := kprobe.Args[0].GetFileArg()
				action := kprobe.Args[1].GetIntArg()
				switch action {
				case 0x02:
					event = p.Colorer.Blue.Sprintf("📝 %-7s", "write")
				case 0x04:
					event = p.Colorer.Blue.Sprintf("📚 %-7s", "read")
				}
				attr = p.Colorer.Cyan.Sprintf("%s", file.Path)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, attr), caps), nil
		case "security_mmap_file":
			event := p.Colorer.Blue.Sprintf("❓ %-7s", "security_mmap_file")
			attr := ""
			if len(kprobe.Args) > 1 && kprobe.Args[0] != nil && kprobe.Args[1] != nil {
				file := kprobe.Args[0].GetFileArg()
				action := kprobe.Args[1].GetUintArg()
				eventTag := "mmap-"
				if action&0x01 != 0 { // PROT_READ
					eventTag += "r"
				}
				if action&0x02 != 0 { // PROT_WRITE
					eventTag += "w"
				}
				if action&0x04 != 0 { // PROT_EXEC
					eventTag += "x"
				}
				event = p.Colorer.Blue.Sprintf("📝 %-7s", eventTag)
				attr = p.Colorer.Cyan.Sprintf("%s", file.Path)
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, attr), caps), nil
		case "security_path_truncate":
			event := p.Colorer.Blue.Sprintf("❓ %-7s", "security_path_truncate")
			attr := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				path := kprobe.Args[0].GetPathArg()
				attr = p.Colorer.Cyan.Sprintf("%s", path.Path)
				event = p.Colorer.Blue.Sprintf("📝 %-7s", "truncate")
			}
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, attr), caps), nil
		default:
			event := p.Colorer.Blue.Sprintf("❓ %-7s", "syscall")
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, kprobe.FunctionName), caps), nil
		}
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		tp := response.GetProcessTracepoint()
		if tp.Process == nil {
			return "", ErrMissingProcessInfo
		}
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, tp.Process)
		switch fmt.Sprintf("%s/%s", tp.Subsys, tp.Event) {
		case "raw_syscalls/sys_enter":
			event := p.Colorer.Blue.Sprintf("☎  %-7s", "syscall")
			sysName := rawSyscallEnter(tp)
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sysName), caps), nil
		default:
			event := p.Colorer.Blue.Sprintf("⁉️ %-7s", "tracepoint")
			return CapTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, tp.Subsys, tp.Event), caps), nil
		}
	case *tetragon.GetEventsResponse_ProcessUprobe:
		uprobe := response.GetProcessUprobe()
		if uprobe.Process == nil {
			return "", ErrMissingProcessInfo
		}
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, uprobe.Process)
		event := p.Colorer.Blue.Sprintf("🕵️ %-7s", "uprobe")
		return CapTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, uprobe.Path, uprobe.Symbol), caps), nil
	case *tetragon.GetEventsResponse_ProcessLsm:
		lsm := response.GetProcessLsm()
		if lsm.Process == nil {
			return "", ErrMissingProcessInfo
		}
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, lsm.Process)
		event := p.Colorer.Blue.Sprintf("🔒 %-7s", "LSM")
		return CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, lsm.FunctionName), caps), nil
	case *tetragon.GetEventsResponse_ProcessUsdt:
		usdt := response.GetProcessUsdt()
		if usdt.Process == nil {
			return "", ErrMissingProcessInfo
		}
		processInfo, caps := p.Colorer.ProcessInfo(response.NodeName, usdt.Process)
		event := p.Colorer.Blue.Sprintf("🕵️ %-7s", "usdt")
		return CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s", event, processInfo, usdt.Path, usdt.Provider, usdt.Name), caps), nil
	}

	return "", fmt.Errorf("%w: %s", ErrUnknownEventType, response.EventType())
}
