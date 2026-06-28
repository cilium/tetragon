// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/pkg/celbpf"
	"github.com/cilium/tetragon/pkg/cgtracker"

	"github.com/cilium/tetragon/pkg/asm"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/elf"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
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

func populateUprobeRegs(m *ebpf.Map, regs []processapi.RegAssignment) error {
	uprobeRegs := processapi.UprobeRegs{}

	n := copy(uprobeRegs.Ass[:], regs)
	if n != len(regs) {
		logger.GetLogger().Warn("register assignments count mismatch", "#regs", len(regs))
	}
	uprobeRegs.Cnt = uint32(n)
	return m.Update(uint32(0), uprobeRegs, ebpf.UpdateAny)
}

func (g *genericUprobe) SetID(id idtable.EntryID) {
	g.tableId = id
}

func (g *genericUprobe) LogAttrs(level slog.Level, msg string, attrs ...slog.Attr) {
	attrs = append(attrs,
		slog.Attr{Key: "policy_name", Value: slog.StringValue(g.policyName)},
		slog.Attr{Key: "path", Value: slog.StringValue(g.path)},
		slog.Attr{Key: "symbol", Value: slog.StringValue(g.symbol)},
		slog.Attr{Key: "address", Value: slog.Uint64Value(g.address)},
	)
	logger.GetLogger().LogAttrs(context.Background(), level, msg, attrs...)
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
		arg := getArg(uprobeEntry, r, a)
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
			reportMergeError[*tracing.MsgGenericUprobeUnix])
	}
	if unix == nil {
		return []observer.Event{}, err
	}

	return []observer.Event{unix}, err
}

func loadSingleUprobeSensor(uprobeEntry *genericUprobe, args sensors.LoadProbeArgs) error {
	load := args.Load

	rewriteProg := make(map[string]func(prog *ebpf.ProgramSpec) error)
	if entry := uprobeEntry.loadArgs.selectors.entry; entry != nil {
		if celbpf.EnabledInBPF() {
			rewriteProg["generic_uprobe_filter_arg"] = entry.CelExprFunctions().RewriteProg
		}
	}
	load.RewriteProg = rewriteProg

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
		mapLoad = append(mapLoad, selectorsMaploads(selector, 0)...)

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

func getUprobeProgramSelector(load *program.Program, uprobeEntry *genericUprobe) *selectors.KernelSelectorState {
	if uprobeEntry != nil {
		if load.RetProbe {
			return uprobeEntry.loadArgs.selectors.retrn
		}
		return uprobeEntry.loadArgs.selectors.entry
	}
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

		rewriteProg := make(map[string]func(prog *ebpf.ProgramSpec) error)

		if entry := uprobeEntry.loadArgs.selectors.entry; entry != nil {
			if celbpf.EnabledInBPF() {
				rewriteProg["generic_uprobe_filter_arg"] = entry.CelExprFunctions().RewriteProg
			}
		}

		load.RewriteProg = rewriteProg

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
			mapLoad = append(mapLoad, selectorsMaploads(selector, uint32(index))...)

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

		if uprobeEntry.address != 0 {
			attach.Addresses = append(attach.Addresses, uprobeEntry.address)
		} else if uprobeEntry.symbol != "" {
			symbol, offset := resolveSymbol(uprobeEntry.symbol)
			attach.Symbols = append(attach.Symbols, symbol)
			attach.Offsets = append(attach.Offsets, offset)
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

type addUprobeIn struct {
	policyName        string
	celExprs          *selectors.CelExprFunctions
	selectorStatsBase uint32
}

type uprobeHas struct {
	sleepableOffload bool
	sleepablePreload bool
	substring        bool
}

func validateMultiUprobeConsistency(uprobes []v1alpha1.UProbeSpec) error {
	if len(uprobes) < 2 {
		return nil
	}

	type pathState struct {
		idx    int
		method string
	}

	pathStates := make(map[string]pathState)

	for i, curr := range uprobes {
		method := ""
		if len(curr.Symbols) != 0 {
			method = "symbols"
		} else if len(curr.Offsets) != 0 {
			method = "offsets"
		} else if len(curr.Addrs) != 0 {
			method = "addrs"
		}

		state, ok := pathStates[curr.Path]
		if !ok {
			pathStates[curr.Path] = pathState{
				idx:    i,
				method: method,
			}
			continue
		}

		if method != state.method {
			return fmt.Errorf(
				"multi-uprobe requires uprobes for the same hook path to use the same addressing method, but uprobe[%d] uses %s while uprobe[%d] uses %s for path %q; disable multiprobe with spec.options: [{name: disable-uprobe-multi, value: \"true\"}]",
				i,
				method,
				state.idx,
				state.method,
				curr.Path,
			)
		}
	}

	return nil
}

type uprobeConfigState struct {
	symbols       int
	offsets       int
	addrs         int
	refCtrOffsets int

	selectors kprobeSelectors

	message string
	tags    []string

	eventConfig       *api.EventConfig
	setRetprobe       bool
	argPrinters       []argPrinter
	argReturnPrinters []argPrinter
}

type uprobeArgConfig struct {
	argTypes [api.EventConfigMaxArgs]int32
	argMeta  [api.EventConfigMaxArgs]uint32
	argIdx   [api.EventConfigMaxArgs]int32

	argPrinters []argPrinter

	regArg     [api.EventConfigMaxRegArgs]api.ConfigRegArg
	allBTFArgs [api.EventConfigMaxArgs][api.MaxBTFArgDepth]api.ConfigBTFArg

	argRetprobe    *v1alpha1.KProbeArg
	argRetprobeIdx int
	preload        bool
}

func validateUprobeSpec(spec *v1alpha1.UProbeSpec, state *uprobeConfigState) error {
	state.symbols = len(spec.Symbols)
	state.offsets = len(spec.Offsets)
	state.addrs = len(spec.Addrs)
	state.refCtrOffsets = len(spec.RefCtrOffsets)

	numAddressMethods := 0
	if state.symbols != 0 {
		numAddressMethods++
	}
	if state.offsets != 0 {
		numAddressMethods++
	}
	if state.addrs != 0 {
		numAddressMethods++
	}

	if numAddressMethods != 1 {
		return errors.New("uprobe needs exactly one of either Symbols, Offsets or Addrs defined")
	}

	if state.refCtrOffsets != 0 {
		if state.symbols != 0 && state.symbols != state.refCtrOffsets {
			return fmt.Errorf("RefCtrOffsets(%d) has different dimension than Symbols(%d)",
				state.refCtrOffsets, state.symbols)
		}
		if state.offsets != 0 && state.offsets != state.refCtrOffsets {
			return fmt.Errorf("RefCtrOffsets(%d) has different dimension than Offsets(%d)",
				state.refCtrOffsets, state.offsets)
		}
	}

	return nil
}

func validateUprobeFeatures(spec *v1alpha1.UProbeSpec, has *uprobeHas) error {
	if selectors.HasOverride(spec.Selectors) {
		if !bpf.HasUprobeRegsChange() {
			return errors.New("can't use override regs action, no kernel support")
		}
		has.sleepableOffload = true
	}

	if selectors.HasOperator(spec.Selectors, selectors.SelectorOpSubString) {
		if !bpf.HasKfunc("bpf_strnstr") {
			return errors.New("can't use SubString operator, no kernel support")
		}
		has.substring = true
	}

	if selectors.HasOperator(spec.Selectors, selectors.SelectorOpSubStringIgnCase) {
		if !bpf.HasKfunc("bpf_strncasestr") {
			return errors.New("can't use SubStringIgnCase operator, no kernel support")
		}
		has.substring = true
	}

	return nil
}

func initUprobeSelectors(spec *v1alpha1.UProbeSpec, in *addUprobeIn, state *uprobeConfigState) error {
	entry, err := selectors.InitKernelSelectorState(&selectors.KernelSelectorArgs{
		Selectors: spec.Selectors,
		Args:      spec.Args,
		Data:      spec.Data,
		IsUprobe:  true,
		CelExprs:  in.celExprs,
	})
	if err != nil {
		return err
	}

	state.selectors = kprobeSelectors{
		entry: entry,
	}

	var retrn *selectors.KernelSelectorState
	if spec.Return {
		retrn, err = selectors.InitKernelReturnSelectorState(spec.Selectors, spec.ReturnArg,
			nil, nil, nil)
		if err != nil {
			// we rely on addUprobe cleanup for entry selector
			return err
		}
	}

	state.selectors.retrn = retrn
	return nil
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
	var celExprs *selectors.CelExprFunctions

	// use multi uprobe only if:
	// - it's not disabled by spec option
	// - there's support detected
	useMulti := !polInfo.specOpts.DisableUprobeMulti && bpf.HasUprobeMulti()

	if useMulti {
		// if we are using multi-uprobe, CEL expressions are shared across all uprobes
		celExprs = &selectors.CelExprFunctions{}
	}

	in := addUprobeIn{
		policyName: polInfo.name,
		celExprs:   celExprs,
	}

	if useMulti {
		if err = validateMultiUprobeConsistency(spec.UProbes); err != nil {
			return nil, err
		}
	}

	var selectorStatsBase uint32
	for _, uprobe := range spec.UProbes {
		if err = appendMacrosSelectors(uprobe.Selectors, spec.SelectorsMacros); err != nil {
			return nil, fmt.Errorf("append macros selectors: %w", err)
		}

		in.selectorStatsBase = selectorStatsBase
		selectorStatsBase += uint32(len(uprobe.Selectors))

		ids, err = addUprobe(&uprobe, ids, &in, &has)
		if err != nil {
			return nil, err
		}
	}

	if useMulti {
		progs, maps, err = createMultiUprobeSensor(polInfo, name, ids, has)
	} else {
		progs, maps, err = createSingleUprobeSensor(polInfo, ids, has)
	}

	if err != nil {
		return nil, err
	}

	maps = append(maps, program.MapUserFrom(base.ExecveMap))
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		maps = append(maps, program.MapUserFrom(base.RingBufEvents))
	}

	if option.Config.ParentsMapEnabled {
		maps = append(maps, program.MapUserFrom(base.ParentBinariesMap))
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

func initUprobeMisc(spec *v1alpha1.UProbeSpec, in *addUprobeIn, state *uprobeConfigState) error {
	var err error

	state.message, err = getPolicyMessage(spec.Message)
	if errors.Is(err, ErrMsgSyntaxShort) || errors.Is(err, ErrMsgSyntaxEscape) {
		return err
	} else if errors.Is(err, ErrMsgSyntaxLong) {
		logger.GetLogger().Warn(fmt.Sprintf("TracingPolicy 'message' field too long, truncated to %d characters", TpMaxMessageLen),
			"policy-name", in.policyName)
	}

	state.tags, err = GetPolicyTags(spec.Tags)
	return err
}

func initUprobeArgs(spec *v1alpha1.UProbeSpec, has *uprobeHas, in *addUprobeIn, state *uprobeConfigState) error {
	argCfg, err := getUprobeArgConfig(spec, has)
	if err != nil {
		return err
	}

	eventConfig := initEventConfig()
	eventConfig.SelStatsBase = in.selectorStatsBase
	eventConfig.ArgType = argCfg.argTypes
	eventConfig.ArgMeta = argCfg.argMeta
	eventConfig.ArgIndex = argCfg.argIdx
	eventConfig.BTFArg = argCfg.allBTFArgs
	eventConfig.RegArg = argCfg.regArg

	setRetprobe, argReturnPrinters, err := getUprobeReturnArg(spec, argCfg, eventConfig)
	if err != nil {
		return err
	}

	state.eventConfig = eventConfig
	state.setRetprobe = setRetprobe
	state.argPrinters = argCfg.argPrinters
	state.argReturnPrinters = argReturnPrinters
	return nil
}

func getUprobeArgConfig(spec *v1alpha1.UProbeSpec, has *uprobeHas) (uprobeArgConfig, error) {
	var cfg uprobeArgConfig

	addArg := func(i int, a *v1alpha1.KProbeArg, data bool) error {
		var preloadArg bool
		argType := gt.GenericTypeFromString(a.Type)

		if data {
			// Data specific config
			if hasPtRegsSource(a) {
				var ok bool

				cfg.regArg[i].Offset, cfg.regArg[i].Size, ok = asm.RegOffsetSize(a.Resolve)
				if !ok {
					return fmt.Errorf("error: Failed to retrieve register argument '%s'", a.Resolve)
				}

				// If we are getting string type from pt_regs register we can safely assume
				// it's from user address, so we need to read it through preload.
				if argType == gt.GenericStringType {
					if !bpf.HasKfunc("bpf_copy_from_user_str") {
						return fmt.Errorf("can't preload string for argument %d", i)
					}
					if cfg.preload {
						return errors.New("error: can't preload more than one argument")
					}
					preloadArg = true
				}
			} else if hasCurrentTaskSource(a) {
				if !bpf.HasProgramLargeSize() {
					return errors.New("error: Resolve flag can't be used for your kernel version. Please update to version 5.4 or higher or disable Resolve flag")
				}
				lastBTFType, btfArg, err := resolveBTFArg("", a, false)
				if err != nil {
					return fmt.Errorf("can't resolve current_task source: %s", a.Resolve)
				}
				cfg.allBTFArgs[i] = btfArg
				argType = findTypeFromBTFType(a, lastBTFType)
			}
		} else {
			// Args specific config
			if a.Resolve != "" {
				lastBTFType, btfArg, err := resolveUserBTFArg(a, spec.BTFPath)
				if err != nil {
					return err
				}

				cfg.allBTFArgs[i] = btfArg
				argType = findTypeFromBTFType(a, lastBTFType)
			}

			if argType == gt.GenericStringType {
				if !bpf.HasKfunc("bpf_copy_from_user_str") {
					return fmt.Errorf("can't preload string for argument %d", i)
				}
				if cfg.preload {
					return errors.New("error: can't preload more than one argument")
				}
				preloadArg = true
			}
		}

		cfg.preload = cfg.preload || preloadArg

		has.sleepablePreload = has.sleepablePreload || cfg.preload

		if argType == gt.GenericInvalidType {
			return fmt.Errorf("Arg(%d) type '%s' unsupported", i, a.Type)
		}
		argMValue, err := getUserMetaValue(a, preloadArg)
		if err != nil {
			return err
		}
		if argReturnCopy(argMValue) {
			cfg.argRetprobe = &spec.Args[i]
			cfg.argRetprobeIdx = i
		}
		if a.Index > 4 {
			return fmt.Errorf("error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index))
		}

		cfg.argTypes[i] = int32(argType)
		cfg.argMeta[i] = uint32(argMValue)
		cfg.argIdx[i] = int32(a.Index)

		cfg.argPrinters = append(cfg.argPrinters, argPrinter{index: i, ty: argType, data: data})
		return nil
	}

	var i int

	// Parse Arguments
	for _, arg := range spec.Args {
		if arg.Source != "" {
			return cfg, fmt.Errorf("standard argument can't have source set '%s'", arg.Source)
		}
		if err := addArg(i, &arg, false); err != nil {
			return cfg, err
		}
		i = i + 1
	}

	// Parse Data
	for _, data := range spec.Data {
		if !hasPtRegsSource(&data) && !hasCurrentTaskSource(&data) {
			return cfg, fmt.Errorf("data argument has wrong source '%s'", data.Source)
		}
		if data.Resolve == "" {
			return cfg, errors.New("data argument missing 'resolve' setup")
		}
		if err := addArg(i, &data, true); err != nil {
			return cfg, err
		}
		i = i + 1
	}

	return cfg, nil
}

func getUprobeReturnArg(spec *v1alpha1.UProbeSpec, argCfg uprobeArgConfig, eventConfig *api.EventConfig) (bool, []argPrinter, error) {
	var argReturnPrinters []argPrinter

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
			return false, nil, errors.New("ReturnArg not specified with Return=true")
		}
		argType := gt.GenericTypeFromString(spec.ReturnArg.Type)
		if argType == gt.GenericInvalidType {
			if spec.ReturnArg.Type == "" {
				return false, nil, errors.New("ReturnArg not specified with Return=true")
			}
			return false, nil, fmt.Errorf("ReturnArg type '%s' unsupported", spec.ReturnArg.Type)
		}
		eventConfig.ArgReturn = int32(argType)
		argP := argPrinter{index: api.ReturnArgIndex, ty: argType}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		eventConfig.ArgReturn = int32(gt.GenericUnsetType)
	}

	setRetprobe := spec.Return
	if argCfg.argRetprobe != nil {
		setRetprobe = true

		argType := gt.GenericTypeFromString(argCfg.argRetprobe.Type)
		eventConfig.ArgReturnCopy = int32(argType)

		argP := argPrinter{index: argCfg.argRetprobeIdx, ty: argType, label: argCfg.argRetprobe.Label}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		eventConfig.ArgReturnCopy = int32(gt.GenericUnsetType)
	}

	return setRetprobe, argReturnPrinters, nil
}

func addUprobe(spec *v1alpha1.UProbeSpec, ids []idtable.EntryID, in *addUprobeIn, has *uprobeHas) ([]idtable.EntryID, error) {
	state := uprobeConfigState{}

	if err := validateUprobeSpec(spec, &state); err != nil {
		return nil, err
	}

	if err := validateUprobeFeatures(spec, has); err != nil {
		return nil, err
	}

	if err := initUprobeSelectors(spec, in, &state); err != nil {
		return nil, err
	}

	if err := initUprobeMisc(spec, in, &state); err != nil {
		return nil, err
	}

	if err := initUprobeArgs(spec, has, in, &state); err != nil {
		return nil, err
	}

	addUprobeEntry := func(sym string, offset uint64, idx int) error {
		var refCtrOffset uint64
		var err error

		if state.refCtrOffsets != 0 {
			refCtrOffset = spec.RefCtrOffsets[idx]
		}

		uprobeEntry := &genericUprobe{
			loadArgs: uprobeLoadArgs{
				retprobe:  state.setRetprobe,
				config:    state.eventConfig,
				selectors: state.selectors,
			},
			tableId:           idtable.UninitializedEntryID,
			path:              spec.Path,
			symbol:            sym,
			address:           offset,
			refCtrOffset:      refCtrOffset,
			policyName:        in.policyName,
			message:           state.message,
			argPrinters:       state.argPrinters,
			argReturnPrinters: state.argReturnPrinters,
			tags:              state.tags,
			pendingEvents:     nil,
		}

		uprobeEntry.pendingEvents, err = lru.New[pendingEventKey, pendingEvent[*tracing.MsgGenericUprobeUnix]](option.Config.RetprobesCacheSize)
		if err != nil {
			return err
		}

		uprobeTable.AddEntry(uprobeEntry)
		id := uprobeEntry.tableId

		state.eventConfig.FuncId = uint32(id.ID)

		ids = append(ids, id)
		return nil
	}

	f, err := elf.OpenSafeELFFile(spec.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if state.symbols != 0 && f.IsStrippedPureGoBinary() {
		tbl, err := f.Pclntab()
		if err != nil {
			return nil, fmt.Errorf("failed to parse pclntab: %w", err)
		}
		for idx, sym := range spec.Symbols {
			if err := checkSymbol(sym); err != nil {
				return nil, fmt.Errorf("failed to parse symbol: %w", err)
			}
			off, ok := tbl.OffsetByName(sym)
			if !ok {
				return nil, fmt.Errorf("failed to resolve symbol: %w", err)
			}
			err = addUprobeEntry(sym, off, idx)
			if err != nil {
				return nil, err
			}
		}
	} else if state.symbols != 0 {
		for idx, sym := range spec.Symbols {
			if err := checkSymbol(sym); err != nil {
				return nil, fmt.Errorf("failed to parse symbol: %w", err)
			}
			err = addUprobeEntry(sym, 0, idx)
			if err != nil {
				return nil, err
			}
		}
	} else if state.offsets != 0 {
		for idx, off := range spec.Offsets {
			err = addUprobeEntry("", off, idx)
			if err != nil {
				return nil, err
			}
		}
	} else if state.addrs != 0 {
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

func createMultiUprobeSensor(polInfo *policyInfo, sensorPath string, multiIDs []idtable.EntryID, has uprobeHas) ([]*program.Program, []*program.Map, error) {
	var multiRetIDs []idtable.EntryID
	var progs []*program.Program
	var maps []*program.Map
	var substringMapEntries int

	for _, id := range multiIDs {
		gu, err := genericUprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		if gu.loadArgs.retprobe {
			multiRetIDs = append(multiRetIDs, id)
		}

		if has.substring && substringMapEntries == 0 {
			substringMapEntries = len(gu.loadArgs.selectors.entry.SubStrings())
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
		SetPolicy(polInfo.name)

	load.SleepableOffload = has.sleepableOffload
	load.SleepablePreload = has.sleepablePreload

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)
	retProbe := program.MapBuilderSensor("retprobe_map", load)

	maps = append(maps, configMap, tailCalls, filterMap, retProbe)
	maps = append(maps, createSelectorMaps(load, getUprobeProgramSelector(load, nil))...)

	if has.substring {
		substringMap := program.MapBuilderSensor("substring_map", load)
		substringMap.SetMaxEntries(substringMapEntries)
		maps = append(maps, substringMap)
	}

	if has.sleepableOffload {
		regsMap := program.MapBuilderProgram("regs_map", load)
		sleepableOffloadMap := program.MapBuilderProgram("sleepable_offload", load)
		sleepableOffloadMap.SetMaxEntries(sleepableOffloadMaxEntries)
		maps = append(maps, regsMap, sleepableOffloadMap)
	}

	if has.sleepablePreload {
		sleepablePreloadMap := program.MapBuilderProgram("sleepable_preload", load)
		sleepablePreloadMap.SetMaxEntries(sleepablePreloadMaxEntries)
		maps = append(maps, sleepablePreloadMap)
	}

	if option.Config.EnableCgTrackerID {
		maps = append(maps, program.MapUser(cgtracker.MapName, load))
	}

	maps = append(maps, polInfo.policyConfMap(load), polInfo.selectorStatsMap(load))

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
			SetPolicy(polInfo.name)

		progs = append(progs, loadret)

		retProbe := program.MapBuilderSensor("retprobe_map", loadret)
		maps = append(maps, retProbe)

		retConfigMap := program.MapBuilderProgram("config_map", loadret)
		maps = append(maps, retConfigMap)

		retFilterMap := program.MapBuilderProgram("filter_map", loadret)
		maps = append(maps, retFilterMap)
		maps = append(maps, createSelectorMaps(loadret, getUprobeProgramSelector(loadret, nil))...)

		retTailCalls := program.MapBuilderProgram("retuprobe_calls", loadret)
		maps = append(maps, retTailCalls)
		retConfigMap.SetMaxEntries(len(multiRetIDs))
		retFilterMap.SetMaxEntries(len(multiRetIDs))
	}

	return progs, maps, nil
}

func createSingleUprobeSensor(polInfo *policyInfo, ids []idtable.EntryID, has uprobeHas) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	for _, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		progs, maps = createUprobeSensorFromEntry(polInfo, uprobeEntry, progs, maps, has)
	}

	return progs, maps, nil
}

func createUprobeSensorFromEntry(polInfo *policyInfo, uprobeEntry *genericUprobe,
	progs []*program.Program, maps []*program.Map, has uprobeHas) ([]*program.Program, []*program.Map) {

	var substringMapEntries int

	if has.substring {
		substringMapEntries = len(uprobeEntry.loadArgs.selectors.entry.SubStrings())
	}

	loadProgName, loadProgRetName := config.GenericUprobeObjs(false)

	pinSymbol := strings.ReplaceAll(uprobeEntry.symbol, ".", "_")
	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("%s %s", uprobeEntry.path, uprobeEntry.symbol),
		"uprobe/generic_uprobe",
		fmt.Sprintf("%d-%s", uprobeEntry.tableId.ID, pinSymbol),
		"generic_uprobe").
		SetLoaderData(uprobeEntry).
		SetPolicy(uprobeEntry.policyName)

	load.SleepableOffload = has.sleepableOffload
	load.SleepablePreload = has.sleepablePreload

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)
	retProbe := program.MapBuilderSensor("retprobe_map", load)
	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	workloadsMap := program.MapBuilderProgram("workloads_map", load)

	maps = append(maps, configMap, tailCalls, filterMap, selMatchBinariesMap, retProbe, workloadsMap)
	maps = append(maps, createSelectorMaps(load, getUprobeProgramSelector(load, uprobeEntry))...)

	if has.substring {
		substringMap := program.MapBuilderSensor("substring_map", load)
		substringMap.SetMaxEntries(substringMapEntries)
		maps = append(maps, substringMap)
	}

	if has.sleepableOffload {
		regsMap := program.MapBuilderProgram("regs_map", load)
		sleepableOffloadMap := program.MapBuilderProgram("sleepable_offload", load)
		sleepableOffloadMap.SetMaxEntries(sleepableOffloadMaxEntries)
		maps = append(maps, regsMap, sleepableOffloadMap)
	}

	if has.sleepablePreload {
		sleepablePreloadMap := program.MapBuilderProgram("sleepable_preload", load)
		sleepablePreloadMap.SetMaxEntries(sleepablePreloadMaxEntries)
		maps = append(maps, sleepablePreloadMap)
	}

	if option.Config.EnableCgTrackerID {
		maps = append(maps, program.MapUser(cgtracker.MapName, load))
	}

	if uprobeEntry.loadArgs.retprobe {
		pinRetProg := fmt.Sprintf("%d-%s_return", uprobeEntry.tableId.ID, pinSymbol)
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

	maps = append(maps, polInfo.policyConfMap(load), polInfo.selectorStatsMap(load))

	return progs, maps
}
