// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"

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

type observerUsdtSensor struct {
	name string
}

var (
	usdtTable idtable.Table
)

type genericUsdt struct {
	tableId idtable.EntryID
	config  *api.EventConfig
	path    string
	target  *elf.UsdtTarget
	// policyName is the name of the policy that this uprobe belongs to
	policyName string
	// message field of the Tracing Policy
	message string
	// argument data printers
	argPrinters []argPrinter
	// tags field of the Tracing Policy
	tags []string
	// selector
	selectors *selectors.KernelSelectorState
}

func (g *genericUsdt) SetID(id idtable.EntryID) {
	g.tableId = id
}

func init() {
	usdt := &observerUsdtSensor{
		name: "usdt sensor",
	}
	sensors.RegisterProbeType("generic_usdt", usdt)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_USDT, handleGenericUsdt)
}

func genericUsdtTableGet(id idtable.EntryID) (*genericUsdt, error) {
	entry, err := usdtTable.GetEntry(id)
	if err != nil {
		return nil, fmt.Errorf("getting entry from usdtTable failed with: %w", err)
	}
	val, ok := entry.(*genericUsdt)
	if !ok {
		return nil, fmt.Errorf("getting entry from usdtTable failed with: got invalid type: %T (%v)", entry, entry)
	}
	return val, nil
}

type addUsdtIn struct {
	sensorPath string
	policyName string
	useMulti   bool
}

func createGenericUsdtSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
) (*sensors.Sensor, error) {
	var (
		progs []*program.Program
		maps  []*program.Map
		ids   []idtable.EntryID
		err   error
	)

	in := addUsdtIn{
		sensorPath: name,
		policyName: polInfo.name,
		useMulti:   !polInfo.specOpts.DisableUprobeMulti && bpf.HasUprobeMulti(),
	}

	for _, usdt := range spec.Usdts {
		ids, err = addUsdt(&usdt, &in, ids)
		if err != nil {
			return nil, err
		}
	}

	if in.useMulti {
		progs, maps, err = createMultiUsdtSensor(ids, polInfo.name)
	} else {
		progs, maps, err = createSingleUsdtSensor(ids)
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
	}, nil
}

func createMultiUsdtSensor(multiIDs []idtable.EntryID, policyName string) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	loadProgName := config.GenericUsdtObjs(true)

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("uprobe_multi (%d functions)", len(multiIDs)),
		"uprobe.multi/generic_usdt",
		"multi_usdt",
		"generic_usdt").
		SetLoaderData(multiIDs).
		SetPolicy(policyName)

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("usdt_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)

	maps = append(maps, configMap, tailCalls, filterMap)

	filterMap.SetMaxEntries(len(multiIDs))
	configMap.SetMaxEntries(len(multiIDs))
	return progs, maps, nil
}

func createSingleUsdtSensor(ids []idtable.EntryID) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	for _, id := range ids {
		usdtEntry, err := genericUsdtTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		progs, maps = createUsdtSensorFromEntry(usdtEntry, progs, maps)
	}

	return progs, maps, nil
}

func createUsdtSensorFromEntry(usdtEntry *genericUsdt,
	progs []*program.Program, maps []*program.Map) ([]*program.Program, []*program.Map) {

	loadProgName := config.GenericUsdtObjs(false)

	attachData := &program.UprobeAttachData{
		Path:         usdtEntry.path,
		Address:      usdtEntry.target.IpRel,
		RefCtrOffset: usdtEntry.target.SemaOff,
	}

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("%s %s %s", usdtEntry.path, usdtEntry.target.Spec.Provider, usdtEntry.target.Spec.Name),
		"uprobe/generic_usdt",
		fmt.Sprintf("%s_%s_%d", usdtEntry.target.Spec.Provider, usdtEntry.target.Spec.Name, usdtEntry.tableId.ID),
		"generic_usdt").
		SetAttachData(attachData).
		SetLoaderData(usdtEntry).
		SetPolicy(usdtEntry.policyName)

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("usdt_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)
	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, configMap, tailCalls, filterMap, selMatchBinariesMap)
	return progs, maps
}

func addUsdt(spec *v1alpha1.UsdtSpec, in *addUsdtIn, ids []idtable.EntryID) ([]idtable.EntryID, error) {
	se, err := elf.OpenSafeELFFile(spec.Path)
	if err != nil {
		return nil, err
	}

	targets, err := se.UsdtTargets()
	if err != nil {
		return nil, err
	}

	tagsField, err := getPolicyTags(spec.Tags)
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

	var argPrinters []argPrinter

	for _, target := range targets {
		if spec.Provider != target.Spec.Provider || spec.Name != target.Spec.Name {
			continue
		}

		config := &api.EventConfig{}

		if len(spec.Args) > api.EventConfigMaxArgs {
			return nil, fmt.Errorf("failed to configured usdt '%s/%s', too many arguments (%d) allowed %d",
				spec.Provider, spec.Name, len(spec.Args), api.EventConfigMaxArgs)
		}

		// Parse Filters into kernel filter logic
		state, err := selectors.InitKernelSelectorState(spec.Selectors, spec.Args, []v1alpha1.KProbeArg{}, nil, nil, nil)
		if err != nil {
			return nil, err
		}

		// Validate argument for set action
		if ok, idx := selectors.HasSetArgIndex(spec); ok {
			// argument index is within usdt args in spec
			if idx > uint32(len(spec.Args)) {
				return nil, fmt.Errorf("failed to configured usdt '%s/%s', set action argument spec index %d out of bounds",
					spec.Provider, spec.Name, idx)
			}

			// usdt spec argument points to existing usdt defined in elf note
			arg := spec.Args[idx]
			if arg.Index > uint32(len(target.Spec.Args)) {
				return nil, fmt.Errorf("failed to configured usdt '%s/%s', argument index %d out of bounds",
					spec.Provider, spec.Name, arg.Index)
			}

			// output argument must be 'deref' type
			tgtArg := &target.Spec.Args[arg.Index]
			if tgtArg.Type != elf.USDT_ARG_TYPE_REG_DEREF {
				return nil, fmt.Errorf("failed to configured usdt '%s/%s', set action argument is not 'deref' type: '%s'",
					spec.Provider, spec.Name, tgtArg.Str)
			}

			// output argument is only allowed to be exactly 4 bytes
			if tgtArg.Size != 4 {
				return nil, fmt.Errorf("failed to configured usdt '%s/%s', set action argument must have size of 4 bytes, current is: %d",
					spec.Provider, spec.Name, tgtArg.Size)
			}
		}

		for cfgIdx, arg := range spec.Args {
			tgtIdx := arg.Index
			if tgtIdx > target.Spec.ArgsCnt {
				return nil, fmt.Errorf("failed to configured usdt '%s/%s', argument index %d out of bounds",
					spec.Provider, spec.Name, tgtIdx)
			}
			tgtArg := &target.Spec.Args[tgtIdx]
			cfgArg := &config.UsdtArg[cfgIdx]

			cfgArg.ValOff = tgtArg.ValOff
			cfgArg.RegOff = uint32(tgtArg.RegOff)
			cfgArg.RegIdxOff = uint32(tgtArg.RegIdxOff)
			cfgArg.Shift = tgtArg.Shift
			cfgArg.Type = tgtArg.Type
			cfgArg.Scale = tgtArg.Scale

			if tgtArg.Signed {
				cfgArg.Signed = 1
			} else {
				cfgArg.Signed = 0
			}

			argType := gt.GenericTypeFromString(arg.Type)

			config.ArgType[cfgIdx] = int32(argType)

			argPrinters = append(argPrinters,
				argPrinter{index: int(arg.Index), ty: argType, label: arg.Label},
			)
		}

		usdtEntry := &genericUsdt{
			tableId:     idtable.UninitializedEntryID,
			config:      config,
			path:        spec.Path,
			target:      target,
			policyName:  in.policyName,
			argPrinters: argPrinters,
			tags:        tagsField,
			message:     msgField,
			selectors:   state,
		}

		usdtTable.AddEntry(usdtEntry)

		id := usdtEntry.tableId
		config.FuncId = uint32(id.ID)

		ids = append(ids, id)
	}

	return ids, nil
}

func (k *observerUsdtSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	load := args.Load
	if entry, ok := load.LoaderData.(*genericUsdt); ok {
		return loadSingleUsdtSensor(entry, args)
	}
	if ids, ok := load.LoaderData.([]idtable.EntryID); ok {
		return loadMultiUsdtSensor(ids, args)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}

func loadSingleUsdtSensor(usdtEntry *genericUsdt, args sensors.LoadProbeArgs) error {
	load := args.Load

	// config_map data
	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, usdtEntry.config)

	// filter_map data
	selBuff := usdtEntry.selectors.Buffer()

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

	if err := program.LoadUprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose); err != nil {
		return err
	}

	logger.GetLogger().Info(fmt.Sprintf("Loaded generic usdt sensor: %s -> %s [%s/%s]",
		args.Load.Name, usdtEntry.path, usdtEntry.target.Spec.Provider, usdtEntry.target.Spec.Name))
	return nil
}

func loadMultiUsdtSensor(ids []idtable.EntryID, args sensors.LoadProbeArgs) error {
	load := args.Load
	data := &program.MultiUprobeAttachData{}
	data.Attach = make(map[string]*program.MultiUprobeAttachSymbolsCookies)

	for index, id := range ids {
		usdtEntry, err := genericUsdtTableGet(id)
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Failed to match id:%d", id), logfields.Error, err)
			return errors.New("failed to match id")
		}

		// config_map data
		var configData bytes.Buffer
		binary.Write(&configData, binary.LittleEndian, usdtEntry.config)

		// filter_map data
		selBuff := usdtEntry.selectors.Buffer()

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

		attach, ok := data.Attach[usdtEntry.path]
		if !ok {
			attach = &program.MultiUprobeAttachSymbolsCookies{}
		}

		attach.Addresses = append(attach.Addresses, usdtEntry.target.IpRel)
		attach.RefCtrOffsets = append(attach.RefCtrOffsets, usdtEntry.target.SemaOff)
		attach.Cookies = append(attach.Cookies, uint64(index))

		data.Attach[usdtEntry.path] = attach
	}

	load.SetAttachData(data)

	if err := program.LoadMultiUprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose); err == nil {
		logger.GetLogger().Info(fmt.Sprintf("Loaded generic usdt multi sensor: %s -> %s",
			load.Name, load.Attach))
	} else {
		return err
	}

	return nil
}

func handleGenericUsdt(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().Warn("Failed to read process call msg", logfields.Error, err)
		return nil, errors.New("failed to read process call msg")
	}

	uprobeUsdt, err := genericUsdtTableGet(idtable.EntryID{ID: int(m.FuncId)})
	if err != nil {
		logger.GetLogger().Warn(fmt.Sprintf("Failed to match id:%d", m.FuncId), logfields.Error, err)
		return nil, errors.New("failed to match id")
	}

	unix := &tracing.MsgGenericUsdtUnix{}
	unix.Msg = &m
	unix.Path = uprobeUsdt.path
	unix.Provider = uprobeUsdt.target.Spec.Provider
	unix.Name = uprobeUsdt.target.Spec.Name
	unix.PolicyName = uprobeUsdt.policyName
	unix.Message = uprobeUsdt.message
	unix.Tags = uprobeUsdt.tags

	// Get argument objects for specific printers/types
	for _, a := range uprobeUsdt.argPrinters {
		arg := getArg(r, a)
		// nop or unknown type (already logged)
		if arg == nil {
			continue
		}
		unix.Args = append(unix.Args, arg)
	}

	return []observer.Event{unix}, err
}
