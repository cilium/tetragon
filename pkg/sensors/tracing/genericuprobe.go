// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/pkg/asm"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/elf"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type observerUprobeSensor struct {
	name string
}

var (
	uprobeTable idtable.Table
)

type uprobeLoadArgs struct {
	selectors kprobeSelectors
	retprobe  bool
	config    *api.EventConfig
}

type genericUprobe struct {
	loadArgs     uprobeLoadArgs
	tableId      idtable.EntryID
	path         string
	symbol       string
	address      uint64
	refCtrOffset uint64
	// policyName is the name of the policy that this uprobe belongs to
	policyName string
	// message field of the Tracing Policy
	message string
	// argument data printers
	argPrinters       []argPrinter
	argReturnPrinters []argPrinter
	// tags field of the Tracing Policy
	tags []string

	// for uprobes that have a retprobe, we maintain the enter events in
	// the map, so that we can merge them when the return event is
	// generated. The events are maintained in the map below, using
	// the retprobe_id (thread_id) and the enter ktime as the key.
	pendingEvents *lru.Cache[pendingEventKey, pendingEvent[*tracing.MsgGenericUprobeUnix]]
}

func (g *genericUprobe) SetID(id idtable.EntryID) {
	g.tableId = id
}

func init() {
	uprobe := &observerUprobeSensor{
		name: "uprobe sensor",
	}
	sensors.RegisterProbeType("generic_uprobe", uprobe)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_UPROBE, handleGenericUprobe)
}

func genericUprobeTableGet(id idtable.EntryID) (*genericUprobe, error) {
	entry, err := uprobeTable.GetEntry(id)
	if err != nil {
		return nil, fmt.Errorf("getting entry from uprobeTable failed with: %w", err)
	}
	val, ok := entry.(*genericUprobe)
	if !ok {
		return nil, fmt.Errorf("getting entry from uprobeTable failed with: got invalid type: %T (%v)", entry, entry)
	}
	return val, nil
}

func handleGenericUprobe(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().Warn("Failed to read process call msg", logfields.Error, err)
		return nil, errors.New("failed to read process call msg")
	}

	uprobeEntry, err := genericUprobeTableGet(idtable.EntryID{ID: int(m.FuncId)})
	if err != nil {
		logger.GetLogger().Warn(fmt.Sprintf("Failed to match id:%d", m.FuncId), logfields.Error, err)
		return nil, errors.New("failed to match id")
	}

	unix := &tracing.MsgGenericUprobeUnix{}
	unix.Msg = &m
	unix.Path = uprobeEntry.path
	unix.Symbol = uprobeEntry.symbol
	unix.Offset = uprobeEntry.address
	unix.RefCtrOffset = uprobeEntry.refCtrOffset
	unix.PolicyName = uprobeEntry.policyName
	unix.Message = uprobeEntry.message
	unix.Tags = uprobeEntry.tags

	returnEvent := m.Common.Flags&processapi.MSG_COMMON_FLAG_RETURN != 0

	var printers []argPrinter
	var ktimeEnter uint64
	if returnEvent {
		// if this a return event, also read the ktime of the enter event
		err = binary.Read(r, binary.LittleEndian, &ktimeEnter)
		if err != nil {
			return nil, errors.New("failed to read ktimeEnter")
		}
		printers = uprobeEntry.argReturnPrinters
	} else {
		ktimeEnter = m.Common.Ktime
		printers = uprobeEntry.argPrinters
	}

	// Get argument objects for specific printers/types
	for _, a := range printers {
		arg := getArg(r, a)
		// nop or unknown type (already logged)
		if arg == nil {
			continue
		}
		if a.data {
			unix.Data = append(unix.Data, arg)
		} else {
			unix.Args = append(unix.Args, arg)
		}
	}

	// Cache return value on merge and run return filters below before
	// passing up to notify hooks.
	if uprobeEntry.loadArgs.retprobe {
		_, unix, _ = retprobeMergeEvents[*tracing.MsgGenericUprobeUnix](
			unix,
			uprobeEntry.pendingEvents,
			returnEvent,
			m.RetProbeId,
			ktimeEnter,
			reportUprobeMergeError)
	}
	if unix == nil {
		return []observer.Event{}, err
	}

	return []observer.Event{unix}, err
}

func loadSingleUprobeSensor(uprobeEntry *genericUprobe, args sensors.LoadProbeArgs) error {
	load := args.Load

	// config_map data
	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, uprobeEntry.loadArgs.config)

	mapLoad := []*program.MapLoad{
		{
			Name: "config_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(uint32(0), configData.Bytes()[:], ebpf.UpdateAny)
			},
		},
	}

	// filter_map data
	var selector *selectors.KernelSelectorState
	if load.RetProbe {
		selector = uprobeEntry.loadArgs.selectors.retrn
	} else {
		selector = uprobeEntry.loadArgs.selectors.entry
	}
	if selector != nil {
		mapLoad = append(mapLoad, &program.MapLoad{
			Name: "filter_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(uint32(0), selector.Buffer(), ebpf.UpdateAny)
			},
		})

		if load.SleepableOffload {
			mapLoad = append(mapLoad,
				&program.MapLoad{
					Name: "regs_map",
					Load: func(m *ebpf.Map, _ string) error {
						return populateUprobeRegs(m, selector.Regs())
					},
				},
			)
		}
	}

	load.MapLoad = append(load.MapLoad, mapLoad...)

	symbol, offset := resolveSymbol(uprobeEntry.symbol)
	attachData := &program.UprobeAttachData{
		Path:         uprobeEntry.path,
		Symbol:       symbol,
		Offset:       offset,
		Address:      uprobeEntry.address,
		RefCtrOffset: uprobeEntry.refCtrOffset,
	}
	load.SetAttachData(attachData)

	if err := program.LoadUprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose); err != nil {
		return err
	}

	logger.GetLogger().Info(fmt.Sprintf("Loaded generic uprobe program: %s -> %s [%s]", args.Load.Name, uprobeEntry.path, uprobeEntry.symbol))
	return nil
}

func checkSymbol(sym string) error {
	_, _, err := parseSymbol(sym)
	return err
}

func resolveSymbol(sym string) (string, uint64) {
	sym, off, err := parseSymbol(sym)
	if err != nil {
		logger.GetLogger().Warn("failed to parse symbol, this should not happen, please report this", logfields.Error, err)
	}
	return sym, off
}

func parseSymbol(sym string) (string, uint64, error) {
	parts := strings.Split(sym, "+")
	if len(parts) == 1 {
		return sym, 0, nil
	}
	if len(parts) != 2 {
		return parts[0], 0, fmt.Errorf("wrong symbol %q", sym)
	}
	sym = parts[0]
	str := parts[1]
	offset, err := strconv.ParseUint(str, 0, 0)
	if err != nil {
		return sym, 0, fmt.Errorf("wrong offset %q", str)
	}
	return sym, offset, nil
}

func loadMultiUprobeSensor(ids []idtable.EntryID, args sensors.LoadProbeArgs) error {
	load := args.Load
	data := &program.MultiUprobeAttachData{}
	data.Attach = make(map[string]*program.MultiUprobeAttachSymbolsCookies)

	for index, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Failed to match id:%d", id), logfields.Error, err)
			return errors.New("failed to match id")
		}

		// config_map data
		var configData bytes.Buffer
		binary.Write(&configData, binary.LittleEndian, uprobeEntry.loadArgs.config)

		mapLoad := []*program.MapLoad{
			{
				Name: "config_map",
				Load: func(m *ebpf.Map, _ string) error {
					return m.Update(uint32(index), configData.Bytes()[:], ebpf.UpdateAny)
				},
			},
		}

		// filter_map data
		var selector *selectors.KernelSelectorState
		if load.RetProbe {
			selector = uprobeEntry.loadArgs.selectors.retrn
		} else {
			selector = uprobeEntry.loadArgs.selectors.entry
		}
		if selector != nil {
			mapLoad = append(mapLoad, &program.MapLoad{
				Name: "filter_map",
				Load: func(m *ebpf.Map, _ string) error {
					return m.Update(uint32(index), selector.Buffer(), ebpf.UpdateAny)
				},
			})

			if load.SleepableOffload {
				mapLoad = append(mapLoad,
					&program.MapLoad{
						Name: "regs_map",
						Load: func(m *ebpf.Map, _ string) error {
							return populateUprobeRegs(m, selector.Regs())
						},
					},
				)
			}
		}

		load.MapLoad = append(load.MapLoad, mapLoad...)

		attach, ok := data.Attach[uprobeEntry.path]
		if !ok {
			attach = &program.MultiUprobeAttachSymbolsCookies{}
		}

		if uprobeEntry.symbol != "" {
			symbol, offset := resolveSymbol(uprobeEntry.symbol)
			attach.Symbols = append(attach.Symbols, symbol)
			attach.Offsets = append(attach.Offsets, offset)
		} else {
			attach.Addresses = append(attach.Addresses, uprobeEntry.address)
		}

		if uprobeEntry.refCtrOffset != 0 {
			attach.RefCtrOffsets = append(attach.RefCtrOffsets, uprobeEntry.refCtrOffset)
		}

		attach.Cookies = append(attach.Cookies, uint64(index))

		data.Attach[uprobeEntry.path] = attach
	}

	load.SetAttachData(data)

	if err := program.LoadMultiUprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose); err == nil {
		logger.GetLogger().Info(fmt.Sprintf("Loaded generic uprobe sensor: %s -> %s", load.Name, load.Attach))
	} else {
		return err
	}

	return nil
}

func (k *observerUprobeSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	load := args.Load

	if entry, ok := load.LoaderData.(*genericUprobe); ok {
		return loadSingleUprobeSensor(entry, args)
	}
	if ids, ok := load.LoaderData.([]idtable.EntryID); ok {
		return loadMultiUprobeSensor(ids, args)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}

func isValidUprobeSelectors(selectors []v1alpha1.KProbeSelector) error {
	for _, s := range selectors {
		if len(s.MatchReturnArgs) > 0 ||
			len(s.MatchNamespaces) > 0 ||
			len(s.MatchNamespaceChanges) > 0 ||
			len(s.MatchCapabilities) > 0 ||
			len(s.MatchCapabilityChanges) > 0 {
			return errors.New("only matchPIDs selector is supported")
		}
	}
	return nil
}

type addUprobeIn struct {
	sensorPath string
	policyName string
	useMulti   bool
}

type uprobeHas struct {
	sleepableOffload bool
}

func createGenericUprobeSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var ids []idtable.EntryID
	var err error
	var has uprobeHas

	in := addUprobeIn{
		sensorPath: name,
		policyName: polInfo.name,

		// use multi uprobe only if:
		// - it's not disabled by spec option
		// - there's support detected
		useMulti: !polInfo.specOpts.DisableUprobeMulti && bpf.HasUprobeMulti(),
	}

	for _, uprobe := range spec.UProbes {
		ids, err = addUprobe(&uprobe, ids, &in, &has)
		if err != nil {
			return nil, err
		}
	}

	if in.useMulti {
		progs, maps, err = createMultiUprobeSensor(name, ids, polInfo.name, has)
	} else {
		progs, maps, err = createSingleUprobeSensor(ids, has)
	}

	if err != nil {
		return nil, err
	}

	maps = append(maps, program.MapUserFrom(base.ExecveMap))
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		maps = append(maps, program.MapUserFrom(base.RingBufEvents))
	}

	return &sensors.Sensor{
		Name:      name,
		Progs:     progs,
		Maps:      maps,
		Policy:    polInfo.name,
		Namespace: polInfo.namespace,
		DestroyHook: func() error {
			var errs error

			for _, id := range ids {
				uprobeEntry, err := genericUprobeTableGet(id)
				if err != nil {
					errs = errors.Join(errs, err)
					continue
				}

				if err = selectors.CleanupKernelSelectorState(uprobeEntry.loadArgs.selectors.entry); err != nil {
					errs = errors.Join(errs, err)
				}

				_, err = uprobeTable.RemoveEntry(id)
				if err != nil {
					errs = errors.Join(errs, err)
				}
			}
			return errs
		},
	}, nil
}

func addUprobe(spec *v1alpha1.UProbeSpec, ids []idtable.EntryID, in *addUprobeIn, has *uprobeHas) ([]idtable.EntryID, error) {
	var argRetprobe *v1alpha1.KProbeArg
	var setRetprobe bool

	symbols := len(spec.Symbols)
	offsets := len(spec.Offsets)
	addrs := len(spec.Addrs)
	refCtrOffsets := len(spec.RefCtrOffsets)

	// uprobe definition spec usanity checks
	if symbols == 0 && offsets == 0 && addrs == 0 {
		return nil, errors.New("uprobe need either Symbols, Offsets or Addrs defined")
	}
	if symbols != 0 && offsets != 0 && addrs != 0 {
		return nil, errors.New("uprobe is defined either only with Symbols, Offsets or Addrs")
	}
	if refCtrOffsets != 0 {
		if symbols != 0 && symbols != refCtrOffsets {
			return nil, fmt.Errorf("RefCtrOffsets(%d) has different dimension than Symbols(%d)",
				refCtrOffsets, symbols)
		}
		if offsets != 0 && offsets != refCtrOffsets {
			return nil, fmt.Errorf("RefCtrOffsets(%d) has different dimension than Offsets(%d)",
				refCtrOffsets, offsets)
		}
	}

	if err := isValidUprobeSelectors(spec.Selectors); err != nil {
		return nil, err
	}

	if selectors.HasOverride(spec.Selectors) {
		if !bpf.HasUprobeRegsChange() {
			return nil, errors.New("can't use override regs action, no kernel support")
		}
		has.sleepableOffload = true
	}

	// Parse Filters into kernel filter logic
	uprobeSelectorState, err := selectors.InitKernelSelectorState(&selectors.KernelSelectorArgs{
		Selectors: spec.Selectors,
		Args:      spec.Args,
		Data:      spec.Data,
		IsUprobe:  true,
	})
	if err != nil {
		return nil, err
	}

	var uprobeRetSelectorState *selectors.KernelSelectorState
	if spec.Return {
		uprobeRetSelectorState, err = selectors.InitKernelReturnSelectorState(spec.Selectors, spec.ReturnArg,
			nil, nil, nil)
		if err != nil {
			return nil, err
		}
	}

	msgField, err := getPolicyMessage(spec.Message)
	if errors.Is(err, ErrMsgSyntaxShort) || errors.Is(err, ErrMsgSyntaxEscape) {
		return nil, err
	} else if errors.Is(err, ErrMsgSyntaxLong) {
		logger.GetLogger().Warn(fmt.Sprintf("TracingPolicy 'message' field too long, truncated to %d characters", TpMaxMessageLen),
			"policy-name", in.policyName)
	}

	var (
		argTypes [api.EventConfigMaxArgs]int32
		argMeta  [api.EventConfigMaxArgs]uint32
		argIdx   [api.EventConfigMaxArgs]int32

		argPrinters       []argPrinter
		argReturnPrinters []argPrinter

		regArg [api.EventConfigMaxRegArgs]api.ConfigRegArg
	)

	tagsField, err := GetPolicyTags(spec.Tags)
	if err != nil {
		return nil, err
	}

	var allBTFArgs [api.EventConfigMaxArgs][api.MaxBTFArgDepth]api.ConfigBTFArg

	addArg := func(i int, a *v1alpha1.KProbeArg, data bool) error {
		argType := gt.GenericTypeFromString(a.Type)

		if data {
			// Data specific config
			if hasPtRegsSource(a) {
				var ok bool

				regArg[i].Offset, regArg[i].Size, ok = asm.RegOffsetSize(a.Resolve)
				if !ok {
					return fmt.Errorf("error: Failed to retrieve register argument '%s'", a.Resolve)
				}
			}
		} else {
			// Args specific config
			if a.Resolve != "" {
				lastBTFType, btfArg, err := resolveUserBTFArg(a, spec.BTFPath)
				if err != nil {
					return err
				}

				allBTFArgs[i] = btfArg
				argType = findTypeFromBTFType(a, lastBTFType)
			}
		}

		if argType == gt.GenericInvalidType {
			return fmt.Errorf("Arg(%d) type '%s' unsupported", i, a.Type)
		}
		argMValue, err := getMetaValue(a)
		if err != nil {
			return err
		}
		if argReturnCopy(argMValue) {
			argRetprobe = &spec.Args[i]
		}
		if a.Index > 4 {
			return fmt.Errorf("error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index))
		}

		argTypes[i] = int32(argType)
		argMeta[i] = uint32(argMValue)
		argIdx[i] = int32(a.Index)

		argPrinters = append(argPrinters, argPrinter{index: i, ty: argType, data: data})
		return nil
	}

	var i int

	// Parse Arguments
	for _, arg := range spec.Args {
		if arg.Source != "" {
			return nil, fmt.Errorf("standard argument can't have source set '%s'", arg.Source)
		}
		if err := addArg(i, &arg, false); err != nil {
			return nil, err
		}
		i = i + 1
	}

	// Parse Data
	for _, data := range spec.Data {
		if !hasPtRegsSource(&data) {
			return nil, fmt.Errorf("data argument has wrong source '%s'", data.Source)
		}
		if data.Resolve == "" {
			return nil, errors.New("data argument missing 'resolve' setup")
		}
		if err := addArg(i, &data, true); err != nil {
			return nil, err
		}
		i = i + 1
	}

	eventConfig := initEventConfig()

	// Parse ReturnArg, we have two types of return arg parsing. We
	// support populating an uprobe buffer from uretprobe hooks. This
	// is used to capture data that is populated by the function hoooked.
	// For example Read calls supply a buffer to the syscall, but we
	// wont have its contents until uretprobe is run. The other type is
	// the f.Return case. These capture the return value of the function
	// without context from the uprobe hook. The BTF argument 'argreturn'
	// instructs the BPF uretprobe program which type of copy to use. And
	// argReturnPrinters tell golang printer piece how to print the event.
	if spec.Return {
		if spec.ReturnArg == nil {
			return nil, errors.New("ReturnArg not specified with Return=true")
		}
		argType := gt.GenericTypeFromString(spec.ReturnArg.Type)
		if argType == gt.GenericInvalidType {
			if spec.ReturnArg.Type == "" {
				return nil, errors.New("ReturnArg not specified with Return=true")
			}
			return nil, fmt.Errorf("ReturnArg type '%s' unsupported", spec.ReturnArg.Type)
		}
		eventConfig.ArgReturn = int32(argType)
		argP := argPrinter{index: api.ReturnArgIndex, ty: argType}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		eventConfig.ArgReturn = int32(gt.GenericUnsetType)
	}

	setRetprobe = spec.Return
	if argRetprobe != nil {
		setRetprobe = true

		argType := gt.GenericTypeFromString(argRetprobe.Type)
		eventConfig.ArgReturnCopy = int32(argType)

		argP := argPrinter{index: int(argRetprobe.Index), ty: argType, label: argRetprobe.Label}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		eventConfig.ArgReturnCopy = int32(gt.GenericUnsetType)
	}

	addUprobeEntry := func(sym string, offset uint64, idx int) error {
		var refCtrOffset uint64

		if refCtrOffsets != 0 {
			refCtrOffset = spec.RefCtrOffsets[idx]
		}

		eventConfig.ArgType = argTypes
		eventConfig.ArgMeta = argMeta
		eventConfig.ArgIndex = argIdx
		eventConfig.BTFArg = allBTFArgs
		eventConfig.RegArg = regArg

		uprobeEntry := &genericUprobe{
			loadArgs: uprobeLoadArgs{
				retprobe: setRetprobe,
				config:   eventConfig,
				selectors: kprobeSelectors{
					entry: uprobeSelectorState,
					retrn: uprobeRetSelectorState,
				},
			},
			tableId:           idtable.UninitializedEntryID,
			path:              spec.Path,
			symbol:            sym,
			address:           offset,
			refCtrOffset:      refCtrOffset,
			policyName:        in.policyName,
			message:           msgField,
			argPrinters:       argPrinters,
			argReturnPrinters: argReturnPrinters,
			tags:              tagsField,
			pendingEvents:     nil,
		}

		uprobeEntry.pendingEvents, err = lru.New[pendingEventKey, pendingEvent[*tracing.MsgGenericUprobeUnix]](option.Config.RetprobesCacheSize)
		if err != nil {
			return err
		}

		uprobeTable.AddEntry(uprobeEntry)
		id := uprobeEntry.tableId

		eventConfig.FuncId = uint32(id.ID)

		ids = append(ids, id)
		return nil
	}

	if symbols != 0 {
		for idx, sym := range spec.Symbols {
			if err := checkSymbol(sym); err != nil {
				return nil, fmt.Errorf("failed to parse symbol: %w", err)
			}
			err = addUprobeEntry(sym, 0, idx)
			if err != nil {
				return nil, err
			}
		}
	} else if offsets != 0 {
		for idx, off := range spec.Offsets {
			err = addUprobeEntry("", off, idx)
			if err != nil {
				return nil, err
			}
		}
	} else if addrs != 0 {
		f, err := elf.OpenSafeELFFile(spec.Path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		for idx, addr := range spec.Addrs {
			off, err := f.OffsetFromAddr(addr)
			if err != nil {
				return nil, err
			}
			err = addUprobeEntry("", off, idx)
			if err != nil {
				return nil, err
			}
		}
	}

	return ids, nil
}

func multiUprobePinPath(sensorPath string) string {
	return sensors.PathJoin(sensorPath, "multi_uprobe")
}

func createMultiUprobeSensor(sensorPath string, multiIDs []idtable.EntryID, policyName string, has uprobeHas) ([]*program.Program, []*program.Map, error) {
	var multiRetIDs []idtable.EntryID
	var progs []*program.Program
	var maps []*program.Map

	for _, id := range multiIDs {
		gu, err := genericUprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		if gu.loadArgs.retprobe {
			multiRetIDs = append(multiRetIDs, id)
		}
	}

	loadProgName, loadProgRetName := config.GenericUprobeObjs(true)

	pinPath := multiUprobePinPath(sensorPath)

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("uprobe_multi (%d functions)", len(multiIDs)),
		"uprobe.multi/generic_uprobe",
		pinPath,
		"generic_uprobe").
		SetLoaderData(multiIDs).
		SetPolicy(policyName)

	load.SleepableOffload = has.sleepableOffload

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)
	retProbe := program.MapBuilderSensor("retprobe_map", load)

	maps = append(maps, configMap, tailCalls, filterMap, retProbe)

	if has.sleepableOffload {
		regsMap := program.MapBuilderProgram("regs_map", load)
		sleepableOffloadMap := program.MapBuilderProgram("sleepable_offload", load)
		sleepableOffloadMap.SetMaxEntries(sleepableOffloadMaxEntries)
		maps = append(maps, regsMap, sleepableOffloadMap)
	}

	filterMap.SetMaxEntries(len(multiIDs))
	configMap.SetMaxEntries(len(multiIDs))

	if len(multiRetIDs) != 0 {
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			fmt.Sprintf("%d retuprobes", len(multiIDs)),
			"uprobe.multi/generic_retuprobe",
			"multi_retuprobe",
			"generic_uprobe").
			SetRetProbe(true).
			SetLoaderData(multiRetIDs).
			SetPolicy(policyName)

		progs = append(progs, loadret)

		retProbe := program.MapBuilderSensor("retprobe_map", loadret)
		maps = append(maps, retProbe)

		retConfigMap := program.MapBuilderProgram("config_map", loadret)
		maps = append(maps, retConfigMap)

		retFilterMap := program.MapBuilderProgram("filter_map", loadret)
		maps = append(maps, retFilterMap)

		retTailCalls := program.MapBuilderProgram("retuprobe_calls", loadret)
		maps = append(maps, retTailCalls)
		retConfigMap.SetMaxEntries(len(multiRetIDs))
		retFilterMap.SetMaxEntries(len(multiRetIDs))
	}

	return progs, maps, nil
}

func createSingleUprobeSensor(ids []idtable.EntryID, has uprobeHas) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	for _, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		progs, maps = createUprobeSensorFromEntry(uprobeEntry, progs, maps, has)
	}

	return progs, maps, nil
}

func createUprobeSensorFromEntry(uprobeEntry *genericUprobe,
	progs []*program.Program, maps []*program.Map, has uprobeHas) ([]*program.Program, []*program.Map) {

	loadProgName, loadProgRetName := config.GenericUprobeObjs(false)

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("%s %s", uprobeEntry.path, uprobeEntry.symbol),
		"uprobe/generic_uprobe",
		fmt.Sprintf("%d-%s", uprobeEntry.tableId.ID, uprobeEntry.symbol),
		"generic_uprobe").
		SetLoaderData(uprobeEntry).
		SetPolicy(uprobeEntry.policyName)

	load.SleepableOffload = has.sleepableOffload

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)
	retProbe := program.MapBuilderSensor("retprobe_map", load)
	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, configMap, tailCalls, filterMap, selMatchBinariesMap, retProbe)

	if has.sleepableOffload {
		regsMap := program.MapBuilderProgram("regs_map", load)
		sleepableOffloadMap := program.MapBuilderProgram("sleepable_offload", load)
		sleepableOffloadMap.SetMaxEntries(sleepableOffloadMaxEntries)
		maps = append(maps, regsMap, sleepableOffloadMap)
	}

	if uprobeEntry.loadArgs.retprobe {
		pinRetProg := fmt.Sprintf("%d-%s_return", uprobeEntry.tableId.ID, uprobeEntry.symbol)
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			fmt.Sprintf("%s %s", uprobeEntry.path, uprobeEntry.symbol),
			"uprobe/generic_retuprobe",
			pinRetProg,
			"generic_uprobe").
			SetRetProbe(true).
			SetLoaderData(uprobeEntry).
			SetPolicy(uprobeEntry.policyName)
		progs = append(progs, loadret)

		retProbe := program.MapBuilderSensor("retprobe_map", loadret)
		maps = append(maps, retProbe)

		retConfigMap := program.MapBuilderProgram("config_map", loadret)
		maps = append(maps, retConfigMap)

		retTailCalls := program.MapBuilderProgram("retuprobe_calls", loadret)
		maps = append(maps, retTailCalls)

		retFilterMap := program.MapBuilderProgram("filter_map", loadret)
		maps = append(maps, retFilterMap)
	}

	return progs, maps
}

func reportUprobeMergeError(curr pendingEvent[*tracing.MsgGenericUprobeUnix], prev pendingEvent[*tracing.MsgGenericUprobeUnix]) {
	currSymbol := "UNKNOWN"
	if curr.ev != nil {
		currSymbol = curr.ev.Symbol
	}
	currType := kprobemetrics.MergeErrorTypeEnter
	if curr.returnEvent {
		currType = kprobemetrics.MergeErrorTypeExit
	}

	prevSymbol := "UNKNOWN"
	if prev.ev != nil {
		prevSymbol = prev.ev.Symbol
	}
	prevType := kprobemetrics.MergeErrorTypeEnter
	if prev.returnEvent {
		prevType = kprobemetrics.MergeErrorTypeExit
	}

	logger.GetLogger().Debug("failed to merge events",
		"currSymbol", currSymbol,
		"currType", currType.String(),
		"prevSymbol", prevSymbol,
		"prevType", prevType.String())
}
