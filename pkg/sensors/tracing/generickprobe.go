// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/api/ops"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/network"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"

	gt "github.com/cilium/tetragon/pkg/generictypes"
)

type observerKprobeSensor struct {
	name string
}

func init() {
	kprobe := &observerKprobeSensor{
		name: "kprobe sensor",
	}
	sensors.RegisterProbeType("generic_kprobe", kprobe)
	sensors.RegisterTracingSensorsAtInit(kprobe.name, kprobe)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_KPROBE, handleGenericKprobe)
}

const (
	CharBufErrorENOMEM      = -1
	CharBufErrorPageFault   = -2
	CharBufErrorTooLarge    = -3
	CharBufSavedForRetprobe = -4
)

func kprobeCharBufErrorToString(e int32) string {
	switch e {
	case CharBufErrorENOMEM:
		return "CharBufErrorENOMEM"
	case CharBufErrorTooLarge:
		return "CharBufErrorBufTooLarge"
	case CharBufErrorPageFault:
		return "CharBufErrorPageFault"
	}
	return "CharBufErrorUnknown"
}

type kprobeLoadArgs struct {
	filters  [4096]byte
	btf      uintptr
	retprobe bool
	syscall  bool
	config   *api.EventConfig
}

type argPrinters struct {
	ty    int
	index int
}

// internal genericKprobe info
type genericKprobe struct {
	loadArgs          kprobeLoadArgs
	argSigPrinters    []argPrinters
	argReturnPrinters []argPrinters
	funcName          string

	// userReturnFilters are filter specs implemented in userspace after
	// receiving events on the return value. We currently use this for return
	// arg filtering.
	userReturnFilters []v1alpha1.ArgSelector

	// for kprobes that have a retprobe, we maintain the enter events in
	// the map, so that we can merge them when the return event is
	// generated. The events are maintained in the map below, using
	// ThreadId as the key.
	pendingEvents map[uint64]pendingEvent

	tableId idtable.EntryID
}

// pendingEvent is an event waiting to be merged with another event.
// This is needed for retprobe probes that generate two events: one at the
// function entry, and one at the function return. We merge these events into
// one, before returning it to the user.
type pendingEvent struct {
	ev          *api.MsgGenericKprobeUnix
	returnEvent bool
}

func (g *genericKprobe) getMapDir(mapDir string) string {
	return path.Join(mapDir, fmt.Sprintf("generickprobe_id:%d_fn:%s", g.tableId.ID, g.funcName)) + "/"
}

func (g *genericKprobe) SetID(id idtable.EntryID) {
	g.tableId = id
}

var (
	// genericKprobeTable is a global table that maintains information for generic kprobes
	genericKprobeTable idtable.Table
)

func genericKprobeTableGet(id idtable.EntryID) (*genericKprobe, error) {
	if entry, err := genericKprobeTable.GetEntry(id); err != nil {
		return nil, fmt.Errorf("getting entry from genericKprobeTable failed with: %w", err)
	} else if val, ok := entry.(*genericKprobe); !ok {
		return nil, fmt.Errorf("getting entry from genericKprobeTable failed with: got invalid type: %T (%v)", entry, entry)
	} else {
		return val, nil
	}
}

func genericKprobeFromBpfLoad(l *program.Program) (*genericKprobe, error) {
	id, ok := l.LoaderData.(idtable.EntryID)
	if !ok {
		return nil, fmt.Errorf("invalid loadData type: expecting idtable.EntryID and got: %T (%v)", l.LoaderData, l.LoaderData)
	}
	return genericKprobeTableGet(id)
}

var (
	MaxFilterIntArgs = 8
)

const (
	argReturnCopyBit = 1 << 4
)

func argReturnCopy(meta int) bool {
	return meta&argReturnCopyBit != 0
}

// meta value format:
// bits
//  0-3 : SizeArgIndex
//    4 : ReturnCopy
func getMetaValue(arg *v1alpha1.KProbeArg) (int, error) {
	var meta int

	if arg.SizeArgIndex > 0 {
		if arg.SizeArgIndex > 15 {
			return 0, fmt.Errorf("invalid SizeArgIndex value (>15): %v", arg.SizeArgIndex)
		}
		meta = int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		meta = meta | argReturnCopyBit
	}
	return meta, nil
}

var binaryNames []v1alpha1.BinarySelector

func initBinaryNames(spec *v1alpha1.KProbeSpec) error {
	for _, s := range spec.Selectors {
		for _, b := range s.MatchBinaries {
			binaryNames = append(binaryNames, b)
		}
	}
	return nil
}

func addGenericKprobeSensors(kprobes []v1alpha1.KProbeSpec, btfBaseFile string) (*sensors.Sensor, error) {
	var progs []*program.Program

	btfobj := bpf.BTFNil
	defer func() {
		// if we return early due to an error, make sure that we don't leak the BTF object
		if btfobj != bpf.BTFNil {
			btfobj.Close()
		}
	}()

	for i := range kprobes {
		f := &kprobes[i]
		var argSigPrinters []argPrinters
		var argReturnPrinters []argPrinters
		var setRetprobe, is_syscall bool
		var argRetprobe *v1alpha1.KProbeArg
		var argsBTFSet [api.MaxArgsSupported]bool

		config := &api.EventConfig{}

		argRetprobe = nil // holds pointer to arg for return handler
		funcName := f.Call

		// Write args into BTF ptr for use with load
		var err error
		btfobj, err = btf.NewBTF()
		if err != nil {
			return nil, err
		}

		if err := btf.ValidateKprobeSpec(btfobj, f); err != nil {
			if warn, ok := err.(*btf.ValidationWarn); ok {
				logger.GetLogger().Warnf("kprobe spec validation: %s", warn)
			} else if e, ok := err.(*btf.ValidationFailed); ok {
				return nil, fmt.Errorf("kprobe spec validation failed: %w", e)
			} else {
				logger.GetLogger().Warnf("invalid or old kprobe spec: %s", err)
			}
		}

		// Parse Arguments
		for j, a := range f.Args {
			argType := gt.GenericTypeFromString(a.Type)
			if argType == gt.GenericInvalidType {
				return nil, fmt.Errorf("Arg(%d) type '%s' unsupported", j, a.Type)
			}
			argMValue, err := getMetaValue(&a)
			if err != nil {
				return nil, err
			}
			if argReturnCopy(argMValue) {
				argRetprobe = &f.Args[j]
			}
			if a.Index > 4 {
				return nil,
					fmt.Errorf("Error add arg: ArgType %s Index %d out of bounds",
						a.Type, int(a.Index))
			}
			config.Arg[a.Index] = int32(argType)
			config.ArgM[a.Index] = uint32(argMValue)

			argsBTFSet[a.Index] = true
			argP := argPrinters{index: j, ty: argType}
			argSigPrinters = append(argSigPrinters, argP)
		}

		// Parse ReturnArg, we have two types of return arg parsing. We
		// support populating a kprobe buffer from kretprobe hooks. This
		// is used to capture data that is populated by the function hoooked.
		// For example Read calls supply a buffer to the syscall, but we
		// wont have its contents until kretprobe is run. The other type is
		// the f.Return case. These capture the return value of the function
		// without context from the kprobe hook. The BTF argument 'argreturn'
		// instructs the BPF kretprobe program which type of copy to use. And
		// argReturnPrinters tell golang printer piece how to print the event.
		if f.Return {
			argType := gt.GenericTypeFromString(f.ReturnArg.Type)
			if argType == gt.GenericInvalidType {
				if f.ReturnArg.Type == "" {
					return nil, fmt.Errorf("ReturnArg not specified with Return=true")
				}
				return nil, fmt.Errorf("ReturnArg type '%s' unsupported", f.ReturnArg.Type)
			}
			config.ArgReturn = int32(argType)
			argsBTFSet[api.ReturnArgIndex] = true
			argP := argPrinters{index: api.ReturnArgIndex, ty: argType}
			argReturnPrinters = append(argReturnPrinters, argP)
		} else {
			config.ArgReturn = int32(0)
		}

		if argRetprobe != nil {
			argsBTFSet[api.ReturnArgIndex] = true
			setRetprobe = true

			argType := gt.GenericTypeFromString(argRetprobe.Type)
			config.ArgReturnCopy = int32(argType)

			argP := argPrinters{index: int(argRetprobe.Index), ty: argType}
			argReturnPrinters = append(argReturnPrinters, argP)
		} else {
			config.ArgReturnCopy = int32(0)
		}

		// Mark remaining arguments as 'nops' the kernel side will skip
		// copying 'nop' args.
		for j, a := range argsBTFSet {
			if a == false {
				if j != api.ReturnArgIndex {
					config.Arg[j] = gt.GenericNopType
					config.ArgM[j] = 0
				}
			}
		}

		// Parse Filters into kernel filter logic
		kernelSelectors, err := selectors.InitKernelSelectors(f)
		if err != nil {
			return nil, err
		}

		// Parse Binary Name into kernel data structures
		if err := initBinaryNames(f); err != nil {
			return nil, err
		}

		hasOverride := selectors.HasOverride(f)
		if hasOverride && !bpf.HasOverrideHelper() {
			return nil, fmt.Errorf("Error override_return bpf helper not available")
		}

		// Copy over userspace return filters
		var userReturnFilters []v1alpha1.ArgSelector
		for _, s := range f.Selectors {
			for _, returnArg := range s.MatchReturnArgs {
				userReturnFilters = append(userReturnFilters, returnArg)
			}
		}

		// Write attributes into BTF ptr for use with load
		is_syscall = f.Syscall
		if !setRetprobe {
			setRetprobe = f.Return
		}

		if is_syscall {
			config.Syscall = 1
		} else {
			config.Syscall = 0

			if hasOverride {
				return nil, fmt.Errorf("Error override action can be used only with syscalls")
			}
		}

		has_sigkill := selectors.MatchActionSigKill(f)
		if has_sigkill {
			config.Sigkill = 1
		} else {
			config.Sigkill = 0
		}

		// create a new entry on the table, and pass its id to BPF-side
		// so that we can do the matching at event-generation time
		kprobeEntry := genericKprobe{
			loadArgs: kprobeLoadArgs{
				filters:  kernelSelectors,
				btf:      uintptr(btfobj),
				retprobe: setRetprobe,
				syscall:  is_syscall,
				config:   config,
			},
			argSigPrinters:    argSigPrinters,
			argReturnPrinters: argReturnPrinters,
			userReturnFilters: userReturnFilters,
			funcName:          funcName,
			pendingEvents:     map[uint64]pendingEvent{},
			tableId:           idtable.UninitializedEntryID,
		}
		genericKprobeTable.AddEntry(&kprobeEntry)

		config.FuncId = uint32(kprobeEntry.tableId.ID)

		loadProgName := "bpf_generic_kprobe.o"
		loadProgRetName := "bpf_generic_retkprobe.o"
		if kernels.EnableLargeProgs() {
			loadProgName = "bpf_generic_kprobe_v53.o"
			loadProgRetName = "bpf_generic_retkprobe_v53.o"
		}

		// NB(kkourt): after we insert the kprobeEntry to the global table
		// (genericKprobeTable), the btf object will need to be released when we remove the
		// entry from the table. We set btfobj to nil to indicate this.
		//
		// Currently, however, we do not remove entries from the global table.
		//
		// Removal is done in the sensor controller goroutine.  One option would be to
		// add a sensorRemove method in the observerSensorImpl, so that each sensor does its
		// own cleanup. Note that in that case, we would need to synchronize access to the
		// table because sensorRemove would be called from the sensor controller goroutine.
		//
		// Alternatively, we could construct the btf object at load time (as we do in the
		// tracepoints case) and release it there, which seems like a simpler option.
		btfobj = bpf.BTFNil

		load := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgName),
			funcName,
			"kprobe/generic_kprobe",
			"kprobe"+"_"+funcName,
			"generic_kprobe").
			SetLoaderData(kprobeEntry.tableId)
		load.Override = hasOverride
		progs = append(progs, load)

		if setRetprobe {
			loadret := program.Builder(
				path.Join(option.Config.HubbleLib, loadProgRetName),
				funcName,
				"kprobe/generic_retkprobe",
				"kretprobe"+"_"+funcName,
				"generic_kprobe").
				SetRetProbe(true).
				SetLoaderData(kprobeEntry.tableId)
			progs = append(progs, loadret)
		}

		logger.GetLogger().Infof("Added generic kprobe sensor: %s -> %s", load.Name, load.Attach)
	}

	return &sensors.Sensor{
		Name:  "__generic_kprobe_sensors__",
		Progs: progs,
		Maps:  []*program.Map{},
	}, nil
}

func loadGenericKprobe(bpfDir, mapDir string, version int, p *program.Program, btf uintptr, genmapDir string, filters [4096]byte, config *api.EventConfig) error {
	progpath := filepath.Join(bpfDir, p.PinPath)
	err, _ := bpf.LoadGenericKprobeProgram(
		version, option.Config.Verbosity,
		p.Override, btf,
		p.Name,
		p.Attach,
		p.Label,
		progpath,
		mapDir,
		genmapDir,
		filters,
		config,
	)
	if err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe sensor: %s -> %s", p.Name, p.Attach)
	} else {
		return err
	}

	m, err := bpf.OpenMap(filepath.Join(mapDir, base.NamesMap.Name))
	if err != nil {
		return err
	}
	for i, b := range binaryNames {
		for _, path := range b.Values {
			writeBinaryMap(i+1, path, m)
		}
	}

	return err
}

func loadGenericKprobeRet(bpfDir, mapDir string, version int, p *program.Program, btf uintptr, genmapDir string, config *api.EventConfig) error {
	err, _ := bpf.LoadGenericKprobeRetProgram(
		version, option.Config.Verbosity, btf,
		p.Name,
		p.Attach,
		p.Label,
		path.Join(bpfDir, p.PinPath),
		mapDir,
		genmapDir,
		config,
	)
	return err
}

func loadGenericKprobeSensor(bpfDir, mapDir string, load *program.Program, version, verbose int) (int, error) {
	gk, err := genericKprobeFromBpfLoad(load)
	if err != nil {
		return 0, err
	}

	genmapDir := gk.getMapDir(mapDir)
	os.Mkdir(genmapDir, os.ModeDir)

	sensors.AllPrograms = append(sensors.AllPrograms, load)
	retprobe := strings.Contains(load.Name, "ret")
	if retprobe {
		return 0, loadGenericKprobeRet(bpfDir, mapDir, version, load, gk.loadArgs.btf, genmapDir, gk.loadArgs.config)
	}

	return 0, loadGenericKprobe(bpfDir, mapDir, version, load, gk.loadArgs.btf, genmapDir, gk.loadArgs.filters, gk.loadArgs.config)
}

func handleGenericKprobeString(r *bytes.Reader) string {
	var b int32

	err := binary.Read(r, binary.LittleEndian, &b)
	if err != nil {
		/* If no size then path walk was not possible and file was either
		 * a mount point or not a "file" at all which can happen if running
		 * without any filters and kernel opens an anonymous inode. For this
		 * lets just report its on "/" all though pid filtering will mostly
		 * catch this.
		 */
		return "/"
	}
	outputStr := make([]byte, b)
	err = binary.Read(r, binary.LittleEndian, &outputStr)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("String with size %d type err", b)
	}

	strVal := string(outputStr[:])
	lenStrVal := len(strVal)
	if lenStrVal > 0 && strVal[lenStrVal-1] == '\x00' {
		strVal = strVal[0 : lenStrVal-1]
	}
	return strVal
}

func ReadArgBytes(r *bytes.Reader, index int) (*api.MsgGenericKprobeArgBytes, error) {
	var bytes, bytes_rd int32
	var arg api.MsgGenericKprobeArgBytes

	if err := binary.Read(r, binary.LittleEndian, &bytes); err != nil {
		return nil, fmt.Errorf("failed to read original size for buffer argument: %w", err)
	}

	arg.Index = uint64(index)
	if bytes == CharBufSavedForRetprobe {
		return &arg, nil
	}
	// bpf-side returned an error
	if bytes < 0 {
		// NB: once we extended arguments to also pass errors, we can change
		// this.
		arg.Value = []byte(kprobeCharBufErrorToString(bytes))
		return &arg, nil
	}
	arg.OrigSize = uint64(bytes)
	if err := binary.Read(r, binary.LittleEndian, &bytes_rd); err != nil {
		return nil, fmt.Errorf("failed to read size for buffer argument: %w", err)
	}

	if bytes_rd > 0 {
		arg.Value = make([]byte, bytes_rd)
		if err := binary.Read(r, binary.LittleEndian, &arg.Value); err != nil {
			return nil, fmt.Errorf("failed to read buffer (size: %d): %w", bytes_rd, err)
		}
	}

	// NB: there are cases (e.g., read()) where it is valid to have an
	// empty (zero-length) buffer.
	return &arg, nil

}

func handleGenericKprobe(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	gk, err := genericKprobeTableGet(idtable.EntryID{ID: int(m.Id)})
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to match id:%d", m.Id)
		return nil, fmt.Errorf("Failed to match id")
	}

	unix := &api.MsgGenericKprobeUnix{}
	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Id = m.Id
	unix.Action = m.ActionId
	unix.FuncName = gk.funcName
	unix.Namespaces = m.Namespaces
	unix.Capabilities = m.Capabilities

	returnEvent := m.Common.Flags > 0

	var printers []argPrinters
	if returnEvent {
		printers = gk.argReturnPrinters
	} else {
		printers = gk.argSigPrinters
	}
	for _, a := range printers {
		switch a.ty {
		case gt.GenericIntType:
			var output int32
			var arg api.MsgGenericKprobeArgInt

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Int type error")
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			unix.Args = append(unix.Args, arg)
		case gt.GenericFileType, gt.GenericFdType:
			var arg api.MsgGenericKprobeArgFile
			var flags uint32
			var b int32

			/* Eat file descriptor its not used in userland */
			if a.ty == gt.GenericFdType {
				binary.Read(r, binary.LittleEndian, &b)
			}

			arg.Index = uint64(a.index)
			arg.Value = handleGenericKprobeString(r)

			// read the first byte that keeps the flags
			err := binary.Read(r, binary.LittleEndian, &flags)
			if err != nil {
				flags = 0
			}

			arg.Flags = flags
			unix.Args = append(unix.Args, arg)
		case gt.GenericPathType:
			var arg api.MsgGenericKprobeArgPath
			var flags uint32

			arg.Index = uint64(a.index)
			arg.Value = handleGenericKprobeString(r)

			// read the first byte that keeps the flags
			err := binary.Read(r, binary.LittleEndian, &flags)
			if err != nil {
				flags = 0
			}

			arg.Flags = flags
			unix.Args = append(unix.Args, arg)
		case gt.GenericFilenameType, gt.GenericStringType:
			var b int32
			var arg api.MsgGenericKprobeArgString

			err := binary.Read(r, binary.LittleEndian, &b)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("StringSz type err")
			}
			outputStr := make([]byte, b)
			err = binary.Read(r, binary.LittleEndian, &outputStr)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("String with size %d type err", b)
			}

			arg.Index = uint64(a.index)
			strVal := string(outputStr[:])
			lenStrVal := len(strVal)
			if lenStrVal > 0 && strVal[lenStrVal-1] == '\x00' {
				strVal = strVal[0 : lenStrVal-1]
			}
			arg.Value = strVal
			unix.Args = append(unix.Args, arg)
		case gt.GenericCredType:
			var cred api.MsgGenericKprobeCred
			var arg api.MsgGenericKprobeArgCred

			err := binary.Read(r, binary.LittleEndian, &cred)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("cred type err")
			}

			arg.Index = uint64(a.index)
			arg.Permitted = cred.Permitted
			arg.Effective = cred.Effective
			arg.Inheritable = cred.Inheritable
			unix.Args = append(unix.Args, arg)
		case gt.GenericCharBuffer, gt.GenericCharIovec:
			if arg, err := ReadArgBytes(r, a.index); err == nil {
				unix.Args = append(unix.Args, *arg)
			} else {
				logger.GetLogger().WithError(err).Warnf("failed to read bytes argument")
			}
		case gt.GenericSkbType:
			var skb api.MsgGenericKprobeSkb
			var arg api.MsgGenericKprobeArgSkb

			err := binary.Read(r, binary.LittleEndian, &skb)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("skb type err")
			}

			arg.Index = uint64(a.index)
			arg.Hash = skb.Hash
			arg.Len = skb.Len
			arg.Priority = skb.Priority
			arg.Mark = skb.Mark
			arg.Saddr = network.GetIP(skb.Saddr, 0).String()
			arg.Daddr = network.GetIP(skb.Daddr, 0).String()
			arg.Sport = uint32(network.SwapByte(uint16(skb.Sport)))
			arg.Dport = uint32(network.SwapByte(uint16(skb.Dport)))
			arg.Proto = skb.Proto
			arg.SecPathLen = skb.SecPathLen
			arg.SecPathOLen = skb.SecPathOLen
			unix.Args = append(unix.Args, arg)
		case gt.GenericSockType:
			var sock api.MsgGenericKprobeSock
			var arg api.MsgGenericKprobeArgSock

			err := binary.Read(r, binary.LittleEndian, &sock)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("sock type err")
			}

			arg.Index = uint64(a.index)
			arg.Family = sock.Family
			arg.Type = sock.Type
			arg.Protocol = sock.Protocol
			arg.Mark = sock.Mark
			arg.Priority = sock.Priority
			arg.Saddr = network.GetIP(sock.Daddr, 0).String()
			arg.Daddr = network.GetIP(sock.Saddr, 0).String()
			arg.Sport = uint32(network.SwapByte(sock.Sport))
			arg.Dport = uint32(network.SwapByte(sock.Dport))
			unix.Args = append(unix.Args, arg)
		case gt.GenericSizeType:
			var output uint64
			var arg api.MsgGenericKprobeArgSize

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			unix.Args = append(unix.Args, arg)
		case gt.GenericNopType:
			// do nothing
		default:
			logger.GetLogger().WithError(err).WithField("event", a).Warnf("Unknown type event")
		}
	}

	// Cache return value on merge and run return filters below before
	// passing up to notify hooks.
	var retArg *api.MsgGenericKprobeArg

	// there are two events for this probe (entry and return)
	if gk.loadArgs.retprobe {
		// if an event exist already, try to merge them. Otherwise, add
		// the one we have in the map.
		curr := pendingEvent{ev: unix, returnEvent: returnEvent}
		if prev, exists := gk.pendingEvents[m.ThreadId]; exists {
			delete(gk.pendingEvents, m.ThreadId)
			unix, retArg = retprobeMerge(prev, curr)
		} else {
			gk.pendingEvents[m.ThreadId] = curr
			unix = nil
			err = fmt.Errorf("pendingEvents")
		}
	}
	if unix == nil {
		return []observer.Event{}, err
	}
	// Last layer of filtering done before Notify upper layers. This is
	// needed for filters and actions that can't be committed in kernel
	// space. For example if we simply dropped a return arg because of
	// a filter we wouldn't be able to cleanup initial event from entry.
	// Alternatively, some actions have no kernel analog, such as pause
	// pod.
	if filterReturnArg(gk.userReturnFilters, retArg) {
		return []observer.Event{}, err
	}

	return []observer.Event{unix}, err
}

func filterReturnArg(userReturnFilters []v1alpha1.ArgSelector, retArg *api.MsgGenericKprobeArg) bool {
	// Short circuit, returnFilter indicates we should eat this event.
	if retArg == nil {
		return false
	}

	// If no filters are specified default to allow.
	if len(userReturnFilters) == 0 {
		return false
	}

	// Multiple selectors will be logical OR together.
	for _, uFilter := range userReturnFilters {
		// MatchPIDs only supported in kernel space because we have
		// full support back to 4.14 kernels.

		// MatchArgs handlers, uFilters only necessary for return
		// arg filters at the moment. Also we simply assume its an
		// int which is naive, but good enough someone should devote
		// more time to make this amazing tech(tm).
		switch uFilter.Operator {
		case "Equal":
			// If retarg Equals any value in the set {Values} accept event
			for _, v := range uFilter.Values {
				if vint, err := strconv.Atoi(v); err == nil {
					switch compare := (*retArg).(type) {
					case api.MsgGenericKprobeArgInt:
						if vint == int(compare.Value) {
							return false
						}
					}
				}
			}
		case "NotEqual":
			inSet := false
			for _, v := range uFilter.Values {
				if vint, err := strconv.Atoi(v); err == nil {
					switch compare := (*retArg).(type) {
					case api.MsgGenericKprobeArgInt:
						if vint == int(compare.Value) {
							inSet = true
						}
					}
				}
			}
			// If retarg was not in set {Values} accept event
			if !inSet {
				return false
			}
		}

	}
	// We walked all selectors and no selectors matched, eat the event.
	return true
}

func reportMergeError(curr pendingEvent, prev pendingEvent) {
	currFn := "UNKNOWN"
	if curr.ev != nil {
		currFn = curr.ev.FuncName
	}
	currType := "enter"
	if curr.returnEvent {
		currType = "exit"
	}

	prevFn := "UNKNOWN"
	if prev.ev != nil {
		prevFn = prev.ev.FuncName
	}
	prevType := "enter"
	if prev.returnEvent {
		prevType = "exit"
	}

	kprobemetrics.MergeErrorsInc(currFn, currType, prevFn, prevType)
	logger.GetLogger().WithFields(logrus.Fields{
		"currFn":   currFn,
		"currType": currType,
		"prevFn":   prevFn,
		"prevType": prevType,
	}).Debugf("failed to merge events")
}

// retprobeMerge merges the two events: the one from the entry probe with the one from the return probe
func retprobeMerge(prev pendingEvent, curr pendingEvent) (*api.MsgGenericKprobeUnix, *api.MsgGenericKprobeArg) {
	var retEv, enterEv *api.MsgGenericKprobeUnix
	var ret *api.MsgGenericKprobeArg

	if prev.returnEvent && !curr.returnEvent {
		retEv = prev.ev
		enterEv = curr.ev
	} else if !prev.returnEvent && curr.returnEvent {
		retEv = curr.ev
		enterEv = prev.ev
	} else {
		reportMergeError(curr, prev)
		return nil, nil
	}

	for _, retArg := range retEv.Args {
		index := retArg.GetIndex()
		if uint64(len(enterEv.Args)) > index {
			enterEv.Args[index] = retArg
		} else {
			enterEv.Args = append(enterEv.Args, retArg)
			ret = &retArg
		}
	}
	return enterEv, ret
}

func (k *observerKprobeSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec, ok := raw.(*v1alpha1.TracingPolicySpec)
	if !ok {
		s, ok := reflect.Indirect(reflect.ValueOf(raw)).FieldByName("TracingPolicySpec").Interface().(v1alpha1.TracingPolicySpec)
		if !ok {
			return nil, nil
		}
		spec = &s
	}

	if len(spec.KProbes) > 0 && len(spec.Tracepoints) > 0 {
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	}
	if len(spec.KProbes) > 0 {
		return addGenericKprobeSensors(spec.KProbes, option.Config.BTF)
	}
	return nil, nil
}

func (k *observerKprobeSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return loadGenericKprobeSensor(args.BPFDir, args.MapDir, args.Load, args.Version, args.Verbose)
}
