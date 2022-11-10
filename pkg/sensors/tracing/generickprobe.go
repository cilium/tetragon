// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
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
	lru "github.com/hashicorp/golang-lru"
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

	MaxKprobesMulti = 100 // MAX_ENTRIES_CONFIG in bpf code
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
	selectors *selectors.KernelSelectorState
	retprobe  bool
	syscall   bool
	config    *api.EventConfig
}

type argPrinters struct {
	ty    int
	index int
}

type pendingEventKey struct {
	threadId   uint64
	ktimeEnter uint64
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
	// the thread_id and the enter ktime as the key.
	pendingEvents *lru.Cache

	tableId idtable.EntryID

	// for kprobes that have a GetUrl action, we store the list of URLs
	// to get.
	urls []string

	// for kprobes that have a DnsRequest action, we store the list of
	// FQDNs to request.
	fqdns []string

	pinPathPrefix string
}

// pendingEvent is an event waiting to be merged with another event.
// This is needed for retprobe probes that generate two events: one at the
// function entry, and one at the function return. We merge these events into
// one, before returning it to the user.
type pendingEvent struct {
	ev          *tracing.MsgGenericKprobeUnix
	returnEvent bool
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
//
//	0-3 : SizeArgIndex
//	  4 : ReturnCopy
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

func createMultiKprobeSensor(sensorPath string, multiIDs, multiRetIDs []idtable.EntryID) ([]*program.Program, []*program.Map) {
	var progs []*program.Program
	var maps []*program.Map

	loadProgName := "bpf_multi_kprobe_v53.o"
	loadProgRetName := "bpf_multi_retkprobe_v53.o"
	if kernels.EnableV60Progs() {
		loadProgName = "bpf_multi_kprobe_v60.o"
		loadProgRetName = "bpf_multi_retkprobe_v60.o"
	}

	pinPath := sensors.PathJoin(sensorPath, "multi_kprobe")

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		"",
		"kprobe.multi/generic_kprobe",
		pinPath,
		"generic_kprobe").
		SetLoaderData(multiIDs)
	progs = append(progs, load)
	logger.GetLogger().Infof("Added multi kprobe sensor: %s (%d functions)", load.Name, len(multiIDs))

	fdinstall := program.MapBuilderPin("fdinstall_map", sensors.PathJoin(sensorPath, "fdinstall_map"), load)
	maps = append(maps, fdinstall)

	configMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "config_map"), load)
	maps = append(maps, configMap)

	tailCalls := program.MapBuilderPin("kprobe_calls", sensors.PathJoin(pinPath, "kp_calls"), load)
	maps = append(maps, tailCalls)

	filterMap := program.MapBuilderPin("filter_map", sensors.PathJoin(pinPath, "filter_map"), load)
	maps = append(maps, filterMap)

	argFilterMaps := program.MapBuilderPin("argfilter_maps", sensors.PathJoin(pinPath, "argfilter_maps"), load)
	maps = append(maps, argFilterMaps)

	retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), load)
	maps = append(maps, retProbe)

	callHeap := program.MapBuilderPin("process_call_heap", sensors.PathJoin(pinPath, "process_call_heap"), load)
	maps = append(maps, callHeap)

	if len(multiRetIDs) != 0 {
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			"",
			"kprobe.multi/generic_retkprobe",
			"multi_retkprobe",
			"generic_kprobe").
			SetRetProbe(true).
			SetLoaderData(multiRetIDs)
		progs = append(progs, loadret)
		logger.GetLogger().Infof("Added multi retkprobe sensor: %s (%d functions)", loadret.Name, len(multiRetIDs))

		retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), loadret)
		maps = append(maps, retProbe)

		retConfigMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "retprobe_config_map"), loadret)
		maps = append(maps, retConfigMap)
	}

	return progs, maps
}

func createGenericKprobeSensor(name string, kprobes []v1alpha1.KProbeSpec) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var multiIDs, multiRetIDs []idtable.EntryID
	var useMulti bool

	sensorPath := name

	loadProgName := "bpf_generic_kprobe.o"
	loadProgRetName := "bpf_generic_retkprobe.o"
	if kernels.EnableV60Progs() {
		loadProgName = "bpf_generic_kprobe_v60.o"
		loadProgRetName = "bpf_generic_retkprobe_v60.o"
	} else if kernels.EnableLargeProgs() {
		loadProgName = "bpf_generic_kprobe_v53.o"
		loadProgRetName = "bpf_generic_retkprobe_v53.o"
	}

	// use multi kprobe only if:
	// - it's not disabled by user
	// - there's support detected
	// - multiple kprobes are defined
	useMulti = !option.Config.DisableKprobeMulti &&
		bpf.HasKprobeMulti() &&
		len(kprobes) > 1 && len(kprobes) < MaxKprobesMulti

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

		var err error
		btfobj, err := btf.NewBTF()
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
		kernelSelectorState, err := selectors.InitKernelSelectorState(f.Selectors, f.Args)
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

		urls := selectors.GetUrls(f)
		fqdns := selectors.GetDnsFQDNs(f)

		// create a new entry on the table, and pass its id to BPF-side
		// so that we can do the matching at event-generation time
		kprobeEntry := genericKprobe{
			loadArgs: kprobeLoadArgs{
				selectors: kernelSelectorState,
				retprobe:  setRetprobe,
				syscall:   is_syscall,
				config:    config,
			},
			argSigPrinters:    argSigPrinters,
			argReturnPrinters: argReturnPrinters,
			userReturnFilters: userReturnFilters,
			funcName:          funcName,
			pendingEvents:     nil,
			tableId:           idtable.UninitializedEntryID,
			urls:              urls,
			fqdns:             fqdns,
		}

		kprobeEntry.pendingEvents, err = lru.New(4096)
		if err != nil {
			return nil, err
		}

		genericKprobeTable.AddEntry(&kprobeEntry)
		tidx := kprobeEntry.tableId.ID
		kprobeEntry.pinPathPrefix = sensors.PathJoin(sensorPath, fmt.Sprintf("gkp-%d", tidx))
		config.FuncId = uint32(tidx)

		if useMulti {
			if setRetprobe {
				multiRetIDs = append(multiRetIDs, kprobeEntry.tableId)
			}
			multiIDs = append(multiIDs, kprobeEntry.tableId)
			continue
		}

		pinPath := kprobeEntry.pinPathPrefix
		pinProg := sensors.PathJoin(pinPath, fmt.Sprintf("%s_prog", kprobeEntry.funcName))

		load := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgName),
			funcName,
			"kprobe/generic_kprobe",
			pinProg,
			"generic_kprobe").
			SetLoaderData(kprobeEntry.tableId)
		load.Override = hasOverride
		progs = append(progs, load)

		fdinstall := program.MapBuilderPin("fdinstall_map", sensors.PathJoin(sensorPath, "fdinstall_map"), load)
		maps = append(maps, fdinstall)

		configMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "config_map"), load)
		maps = append(maps, configMap)

		tailCalls := program.MapBuilderPin("kprobe_calls", sensors.PathJoin(pinPath, "kp_calls"), load)
		maps = append(maps, tailCalls)

		filterMap := program.MapBuilderPin("filter_map", sensors.PathJoin(pinPath, "filter_map"), load)
		maps = append(maps, filterMap)

		argFilterMaps := program.MapBuilderPin("argfilter_maps", sensors.PathJoin(pinPath, "argfilter_maps"), load)
		maps = append(maps, argFilterMaps)

		retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), load)
		maps = append(maps, retProbe)

		callHeap := program.MapBuilderPin("process_call_heap", sensors.PathJoin(pinPath, "process_call_heap"), load)
		maps = append(maps, callHeap)

		if setRetprobe {
			pinRetProg := sensors.PathJoin(pinPath, fmt.Sprintf("%s_ret_prog", kprobeEntry.funcName))
			loadret := program.Builder(
				path.Join(option.Config.HubbleLib, loadProgRetName),
				funcName,
				"kprobe/generic_retkprobe",
				pinRetProg,
				"generic_kprobe").
				SetRetProbe(true).
				SetLoaderData(kprobeEntry.tableId)
			progs = append(progs, loadret)

			retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), loadret)
			maps = append(maps, retProbe)

			retConfigMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "retprobe_config_map"), loadret)
			maps = append(maps, retConfigMap)

			// add maps with non-default paths (pins) to the retprobe
			program.MapBuilderPin("process_call_heap", sensors.PathJoin(pinPath, "process_call_heap"), load)
			program.MapBuilderPin("fdinstall_map", sensors.PathJoin(sensorPath, "fdinstall_map"), loadret)
		}

		logger.GetLogger().Infof("Added generic kprobe sensor: %s -> %s", load.Name, load.Attach)
	}

	if len(multiIDs) != 0 {
		progs, maps = createMultiKprobeSensor(sensorPath, multiIDs, multiRetIDs)
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
	}, nil
}

// ReloadGenericKprobeSelectors will reload a kprobe by unlinking it, generating new
// selector data and updating filter_map, and then relinking the kprobe (entry).
//
// This is intended for speeding up testing, so DO NOT USE elsewhere without
// checking its implementation first because limitations may exist (e.g,. the
// config map is not updated, the retprobe is not reloaded, userspace return filters are not updated, etc.).
func ReloadGenericKprobeSelectors(kpSensor *sensors.Sensor, conf *v1alpha1.KProbeSpec) error {
	// The first program should be the (entry) kprobe, and that's the only
	// one we will reload. We could reload the retprobe, but the assumption
	// is that we don't need to, because it will never be executed if the
	// entry probe is not loaded.
	kprobeProg := kpSensor.Progs[0]
	if kprobeProg.Label != "kprobe/generic_kprobe" {
		return fmt.Errorf("first program %+v does not seem to be the entry kprobe", kprobeProg)
	}

	gk, err := genericKprobeFromBpfLoad(kprobeProg)
	if err != nil {
		return err
	}

	if err := kprobeProg.Unlink(); err != nil {
		return fmt.Errorf("unlinking %v failed: %s", kprobeProg, err)
	}

	kState, err := selectors.InitKernelSelectorState(conf.Selectors, conf.Args)
	if err != nil {
		return err
	}

	if err := updateSelectors(kState, kprobeProg.PinMap, gk.pinPathPrefix); err != nil {
		return err
	}

	if err := kprobeProg.Relink(); err != nil {
		return fmt.Errorf("failed relinking %v: %w", kprobeProg, err)
	}

	return nil
}

func loadSingleKprobeSensor(id idtable.EntryID, bpfDir, mapDir string, load *program.Program, version, verbose int) error {
	gk, err := genericKprobeTableGet(id)
	if err != nil {
		return err
	}

	if !load.RetProbe {
		load.MapLoad = append(load.MapLoad, selectorsMaploads(gk.loadArgs.selectors, gk.pinPathPrefix, 0)...)
	}

	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, gk.loadArgs.config)
	config := &program.MapLoad{
		Index: 0,
		Name:  "config_map",
		Load: func(m *ebpf.Map, index uint32) error {
			return m.Update(index, configData.Bytes()[:], ebpf.UpdateAny)
		},
	}
	load.MapLoad = append(load.MapLoad, config)

	sensors.AllPrograms = append(sensors.AllPrograms, load)

	if err := program.LoadKprobeProgram(bpfDir, mapDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe program: %s -> %s", load.Name, load.Attach)
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

func loadMultiKprobeSensor(ids []idtable.EntryID, bpfDir, mapDir string, load *program.Program, version, verbose int) error {
	sensors.AllPrograms = append(sensors.AllPrograms, load)

	bin_buf := make([]bytes.Buffer, len(ids))

	for index, id := range ids {
		gk, err := genericKprobeTableGet(id)
		if err != nil {
			return err
		}

		if !load.RetProbe {
			load.MapLoad = append(load.MapLoad, selectorsMaploads(gk.loadArgs.selectors, gk.pinPathPrefix, uint32(index))...)
		}

		binary.Write(&bin_buf[index], binary.LittleEndian, gk.loadArgs.config)
		config := &program.MapLoad{
			Index: uint32(index),
			Name:  "config_map",
			Load: func(m *ebpf.Map, index uint32) error {
				return m.Update(index, bin_buf[index].Bytes()[:], ebpf.UpdateAny)
			},
		}
		load.MapLoad = append(load.MapLoad, config)

		load.MultiSymbols = append(load.MultiSymbols, gk.funcName)
		load.MultiCookies = append(load.MultiCookies, uint64(index))
	}

	if err := program.LoadMultiKprobeProgram(bpfDir, mapDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe sensor: %s -> %s", load.Name, load.Attach)
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

func loadGenericKprobeSensor(bpfDir, mapDir string, load *program.Program, version, verbose int) error {
	if id, ok := load.LoaderData.(idtable.EntryID); ok {
		return loadSingleKprobeSensor(id, bpfDir, mapDir, load, version, verbose)
	}
	if ids, ok := load.LoaderData.([]idtable.EntryID); ok {
		return loadMultiKprobeSensor(ids, bpfDir, mapDir, load, version, verbose)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
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

func getUrl(url string) {
	// We fire and forget URLs, and we don't care if they hit or not.
	http.Get(url)
}

func dnsLookup(fqdn string) {
	// We fire and forget DNS lookups, and we don't care if they hit or not.
	net.LookupIP(fqdn)
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

	switch m.ActionId {
	case selectors.ActionTypeGetUrl:
		for _, url := range gk.urls {
			logger.GetLogger().WithField("URL", url).Trace("Get URL Action")
			getUrl(url)
		}
	case selectors.ActionTypeDnsLookup:
		for _, fqdn := range gk.fqdns {
			logger.GetLogger().WithField("FQDN", fqdn).Trace("DNS lookup")
			dnsLookup(fqdn)
		}
	}

	unix := &tracing.MsgGenericKprobeUnix{}
	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Id = m.Id
	unix.Action = m.ActionId
	unix.FuncName = gk.funcName
	unix.Namespaces = m.Namespaces
	unix.Capabilities = m.Capabilities

	returnEvent := m.Common.Flags > 0

	var ktimeEnter uint64
	var printers []argPrinters
	if returnEvent {
		// if this a return event, also read the ktime of the enter event
		err := binary.Read(r, binary.LittleEndian, &ktimeEnter)
		if err != nil {
			return nil, fmt.Errorf("failed to read ktimeEnter")
		}
		printers = gk.argReturnPrinters
	} else {
		ktimeEnter = m.Common.Ktime
		printers = gk.argSigPrinters
	}

	for _, a := range printers {
		switch a.ty {
		case gt.GenericIntType, gt.GenericS32Type:
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
		case gt.GenericSizeType, gt.GenericU64Type:
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
		case gt.GenericBpfAttr:
			var output api.MsgGenericKprobeBpfAttr
			var arg api.MsgGenericKprobeArgBpfAttr

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("bpf_attr type error")
			}
			arg.ProgType = output.ProgType
			arg.InsnCnt = output.InsnCnt
			length := bytes.IndexByte(output.ProgName[:], 0) // trim tailing null bytes
			arg.ProgName = string(output.ProgName[:length])
			unix.Args = append(unix.Args, arg)
		case gt.GenericPerfEvent:
			var output api.MsgGenericKprobePerfEvent
			var arg api.MsgGenericKprobeArgPerfEvent

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("perf_event type error")
			}
			length := bytes.IndexByte(output.KprobeFunc[:], 0) // trim tailing null bytes
			arg.KprobeFunc = string(output.KprobeFunc[:length])
			arg.Type = output.Type
			arg.Config = output.Config
			arg.ProbeOffset = output.ProbeOffset
			unix.Args = append(unix.Args, arg)
		case gt.GenericBpfMap:
			var output api.MsgGenericKprobeBpfMap
			var arg api.MsgGenericKprobeArgBpfMap

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("bpf_map type error")
			}

			arg.MapType = output.MapType
			arg.KeySize = output.KeySize
			arg.ValueSize = output.ValueSize
			arg.MaxEntries = output.MaxEntries
			length := bytes.IndexByte(output.MapName[:], 0) // trim tailing null bytes
			arg.MapName = string(output.MapName[:length])
			unix.Args = append(unix.Args, arg)
		case gt.GenericU32Type:
			var output uint32
			var arg api.MsgGenericKprobeArgUInt

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("UInt type error")
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			unix.Args = append(unix.Args, arg)
		case gt.GenericUserNamespace:
			var output api.MsgGenericKprobeUserNamespace
			var arg api.MsgGenericKprobeArgUserNamespace

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("user_namespace type error")
			}
			arg.Level = output.Level
			arg.Owner = output.Owner
			arg.Group = output.Group
			arg.NsInum = output.NsInum
			unix.Args = append(unix.Args, arg)
		case gt.GenericCapability:
			var output api.MsgGenericKprobeCapability
			var arg api.MsgGenericKprobeArgCapability

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("capability type error")
			}
			arg.Value = output.Value
			unix.Args = append(unix.Args, arg)
		default:
			logger.GetLogger().WithError(err).WithField("event-type", a.ty).Warnf("Unknown event type")
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
		key := pendingEventKey{threadId: m.ThreadId, ktimeEnter: ktimeEnter}

		if data, exists := gk.pendingEvents.Get(key); exists {
			prev, ok := data.(pendingEvent)
			if !ok {
				return nil, fmt.Errorf("Internal error: wrong type in pendingEvents")
			}
			gk.pendingEvents.Remove(key)
			unix, retArg = retprobeMerge(prev, curr)
		} else {
			gk.pendingEvents.Add(key, curr)
			kprobemetrics.MergePushedInc()
			unix = nil
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
func retprobeMerge(prev pendingEvent, curr pendingEvent) (*tracing.MsgGenericKprobeUnix, *api.MsgGenericKprobeArg) {
	var retEv, enterEv *tracing.MsgGenericKprobeUnix
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

	kprobemetrics.MergeOkTotalInc()

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
	name := fmt.Sprintf("gkp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))

	if len(spec.KProbes) > 0 && len(spec.Tracepoints) > 0 {
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	}
	if len(spec.KProbes) > 0 {
		return createGenericKprobeSensor(name, spec.KProbes)
	}
	return nil, nil
}

func (k *observerKprobeSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadGenericKprobeSensor(args.BPFDir, args.MapDir, args.Load, args.Version, args.Verbose)
}
