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

	"github.com/cilium/tetragon/pkg/api/ops"
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

type genericUprobe struct {
	tableId      idtable.EntryID
	config       *api.EventConfig
	path         string
	symbol       string
	address      uint64
	refCtrOffset uint64
	selectors    *selectors.KernelSelectorState
	// policyName is the name of the policy that this uprobe belongs to
	policyName string
	// message field of the Tracing Policy
	message string
	// argument data printers
	argPrinters []argPrinter
	// tags field of the Tracing Policy
	tags []string
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

	// Get argument objects for specific printers/types
	for _, a := range uprobeEntry.argPrinters {
		arg := getArg(r, a)
		// nop or unknown type (already logged)
		if arg == nil {
			continue
		}
		unix.Args = append(unix.Args, arg)
	}

	return []observer.Event{unix}, err
}

func loadSingleUprobeSensor(uprobeEntry *genericUprobe, args sensors.LoadProbeArgs) error {
	load := args.Load

	// config_map data
	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, uprobeEntry.config)

	// filter_map data
	selBuff := uprobeEntry.selectors.Buffer()

	mapLoad := []*program.MapLoad{
		{
			Name: "config_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(uint32(0), configData.Bytes()[:], ebpf.UpdateAny)
			},
		},
		{
			Name: "filter_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(uint32(0), selBuff[:], ebpf.UpdateAny)
			},
		},
	}

	load.MapLoad = append(load.MapLoad, mapLoad...)

	if load.SleepableOffload {
		load.MapLoad = append(load.MapLoad,
			&program.MapLoad{
				Name: "regs_map",
				Load: func(m *ebpf.Map, _ string) error {
					return populateUprobeRegs(m, uprobeEntry.selectors.Regs())
				},
			},
		)
	}

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
		binary.Write(&configData, binary.LittleEndian, uprobeEntry.config)

		// filter_map data
		selBuff := uprobeEntry.selectors.Buffer()

		mapLoad := []*program.MapLoad{
			{
				Name: "config_map",
				Load: func(m *ebpf.Map, _ string) error {
					return m.Update(uint32(index), configData.Bytes()[:], ebpf.UpdateAny)
				},
			},
			{
				Name: "filter_map",
				Load: func(m *ebpf.Map, _ string) error {
					return m.Update(uint32(index), selBuff[:], ebpf.UpdateAny)
				},
			},
		}
		load.MapLoad = append(load.MapLoad, mapLoad...)

		if load.SleepableOffload {
			load.MapLoad = append(load.MapLoad,
				&program.MapLoad{
					Name: "regs_map",
					Load: func(m *ebpf.Map, _ string) error {
						return populateUprobeRegs(m, uprobeEntry.selectors.Regs())
					},
				},
			)
		}

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
		if len(s.MatchArgs) > 0 ||
			len(s.MatchReturnArgs) > 0 ||
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

func createGenericUprobeSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var ids []idtable.EntryID
	var err error

	in := addUprobeIn{
		sensorPath: name,
		policyName: polInfo.name,

		// use multi kprobe only if:
		// - it's not disabled by spec option
		// - there's support detected
		useMulti: !polInfo.specOpts.DisableUprobeMulti && bpf.HasUprobeMulti(),
	}

	hasRegsOverrideAction := false

	for _, uprobe := range spec.UProbes {
		ids, err = addUprobe(&uprobe, ids, &in)
		if err != nil {
			return nil, err
		}

		hasRegsOverrideAction = hasRegsOverrideAction || selectors.HasOverride(uprobe.Selectors)
	}

	hasSleepableOffload := hasRegsOverrideAction && bpf.HasUprobeRegsChange()

	if in.useMulti {
		progs, maps, err = createMultiUprobeSensor(name, ids, polInfo.name, hasSleepableOffload)
	} else {
		progs, maps, err = createSingleUprobeSensor(ids, hasSleepableOffload)
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

				if err = selectors.CleanupKernelSelectorState(uprobeEntry.selectors); err != nil {
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

func addUprobe(spec *v1alpha1.UProbeSpec, ids []idtable.EntryID, in *addUprobeIn) ([]idtable.EntryID, error) {
	var args []v1alpha1.KProbeArg

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

	if selectors.HasOverride(spec.Selectors) && !bpf.HasUprobeRegsChange() {
		return nil, errors.New("can't use override regs action, no kernel support")
	}

	// Parse Filters into kernel filter logic
	uprobeSelectorState, err := selectors.InitKernelSelectorState(&selectors.KernelSelectorArgs{
		Selectors: spec.Selectors,
		Args:      args,
		Data:      []v1alpha1.KProbeArg{},
		IsUprobe:  true,
	})
	if err != nil {
		return nil, err
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

		argPrinters []argPrinter
	)

	tagsField, err := getPolicyTags(spec.Tags)
	if err != nil {
		return nil, err
	}

	// Parse Arguments
	for i, a := range spec.Args {
		argType := gt.GenericTypeFromString(a.Type)
		if argType == gt.GenericInvalidType {
			return nil, fmt.Errorf("Arg(%d) type '%s' unsupported", i, a.Type)
		}
		argMValue, err := getMetaValue(&a)
		if err != nil {
			return nil, err
		}
		if a.Index > 4 {
			return nil, fmt.Errorf("error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index))
		}

		if a.Resolve != "" {
			return nil, errors.New("resolving attributes for Uprobes is not supported")
		}
		argTypes[i] = int32(argType)
		argMeta[i] = uint32(argMValue)
		argIdx[i] = int32(a.Index)

		argPrinters = append(argPrinters, argPrinter{index: i, ty: argType})
	}

	addUprobeEntry := func(sym string, offset uint64, idx int) {
		var refCtrOffset uint64

		if refCtrOffsets != 0 {
			refCtrOffset = spec.RefCtrOffsets[idx]
		}

		config := initEventConfig()
		config.ArgType = argTypes
		config.ArgMeta = argMeta
		config.ArgIndex = argIdx

		uprobeEntry := &genericUprobe{
			tableId:      idtable.UninitializedEntryID,
			config:       config,
			path:         spec.Path,
			symbol:       sym,
			address:      offset,
			refCtrOffset: refCtrOffset,
			selectors:    uprobeSelectorState,
			policyName:   in.policyName,
			message:      msgField,
			argPrinters:  argPrinters,
			tags:         tagsField,
		}

		uprobeTable.AddEntry(uprobeEntry)
		id := uprobeEntry.tableId

		config.FuncId = uint32(id.ID)

		ids = append(ids, id)
	}

	if symbols != 0 {
		for idx, sym := range spec.Symbols {
			if err := checkSymbol(sym); err != nil {
				return nil, fmt.Errorf("failed to parse symbol: %w", err)
			}
			addUprobeEntry(sym, 0, idx)
		}
	} else if offsets != 0 {
		for idx, off := range spec.Offsets {
			addUprobeEntry("", off, idx)
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
			addUprobeEntry("", off, idx)
		}
	}

	return ids, nil
}

func multiUprobePinPath(sensorPath string) string {
	return sensors.PathJoin(sensorPath, "multi_uprobe")
}

func createMultiUprobeSensor(sensorPath string, multiIDs []idtable.EntryID, policyName string, hasSleepableOffload bool) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	loadProgName := config.GenericUprobeObjs(true)

	pinPath := multiUprobePinPath(sensorPath)

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("uprobe_multi (%d functions)", len(multiIDs)),
		"uprobe.multi/generic_uprobe",
		pinPath,
		"generic_uprobe").
		SetLoaderData(multiIDs).
		SetPolicy(policyName)

	load.SleepableOffload = hasSleepableOffload

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)

	maps = append(maps, configMap, tailCalls, filterMap)

	if hasSleepableOffload {
		regsMap := program.MapBuilderProgram("regs_map", load)
		sleepableOffloadMap := program.MapBuilderProgram("sleepable_offload", load)
		sleepableOffloadMap.SetMaxEntries(sleepableOffloadMaxEntries)
		maps = append(maps, regsMap, sleepableOffloadMap)
	}

	filterMap.SetMaxEntries(len(multiIDs))
	configMap.SetMaxEntries(len(multiIDs))
	return progs, maps, nil
}

func createSingleUprobeSensor(ids []idtable.EntryID, hasSleepableOffload bool) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	for _, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		progs, maps = createUprobeSensorFromEntry(uprobeEntry, progs, maps, hasSleepableOffload)
	}

	return progs, maps, nil
}

func createUprobeSensorFromEntry(uprobeEntry *genericUprobe,
	progs []*program.Program, maps []*program.Map, hasSleepableOffload bool) ([]*program.Program, []*program.Map) {

	loadProgName := config.GenericUprobeObjs(false)

	symbol, offset := resolveSymbol(uprobeEntry.symbol)

	attachData := &program.UprobeAttachData{
		Path:         uprobeEntry.path,
		Symbol:       symbol,
		Offset:       offset,
		Address:      uprobeEntry.address,
		RefCtrOffset: uprobeEntry.refCtrOffset,
	}

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("%s %s", uprobeEntry.path, uprobeEntry.symbol),
		"uprobe/generic_uprobe",
		fmt.Sprintf("%d-%s", uprobeEntry.tableId.ID, uprobeEntry.symbol),
		"generic_uprobe").
		SetAttachData(attachData).
		SetLoaderData(uprobeEntry).
		SetPolicy(uprobeEntry.policyName)

	load.SleepableOffload = hasSleepableOffload

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)
	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, configMap, tailCalls, filterMap, selMatchBinariesMap)

	if hasSleepableOffload {
		regsMap := program.MapBuilderProgram("regs_map", load)
		sleepableOffloadMap := program.MapBuilderProgram("sleepable_offload", load)
		sleepableOffloadMap.SetMaxEntries(sleepableOffloadMaxEntries)
		maps = append(maps, regsMap, sleepableOffloadMap)
	}

	return progs, maps
}
