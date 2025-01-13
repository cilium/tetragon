// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

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
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
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
	tableId       idtable.EntryID
	pinPathPrefix string
	config        *api.EventConfig
	path          string
	symbol        string
	selectors     *selectors.KernelSelectorState
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
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	uprobeEntry, err := genericUprobeTableGet(idtable.EntryID{ID: int(m.FuncId)})
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to match id:%d", m.FuncId)
		return nil, fmt.Errorf("Failed to match id")
	}

	unix := &tracing.MsgGenericUprobeUnix{}
	unix.Msg = &m
	unix.Path = uprobeEntry.path
	unix.Symbol = uprobeEntry.symbol
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
			Index: 0,
			Name:  "config_map",
			Load: func(m *ebpf.Map, _ string, index uint32) error {
				return m.Update(index, configData.Bytes()[:], ebpf.UpdateAny)
			},
		},
		{
			Index: 0,
			Name:  "filter_map",
			Load: func(m *ebpf.Map, _ string, index uint32) error {
				return m.Update(index, selBuff[:], ebpf.UpdateAny)
			},
		},
	}

	load.MapLoad = append(load.MapLoad, mapLoad...)

	if err := program.LoadUprobeProgram(args.BPFDir, args.Load, args.Verbose); err != nil {
		return err
	}

	logger.GetLogger().Infof("Loaded generic uprobe program: %s -> %s [%s]", args.Load.Name, uprobeEntry.path, uprobeEntry.symbol)
	return nil
}

func loadMultiUprobeSensor(ids []idtable.EntryID, args sensors.LoadProbeArgs) error {
	load := args.Load
	data := &program.MultiUprobeAttachData{}
	data.Attach = make(map[string]*program.MultiUprobeAttachSymbolsCookies)

	for index, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Failed to match id:%d", id)
			return fmt.Errorf("Failed to match id")
		}

		// config_map data
		var configData bytes.Buffer
		binary.Write(&configData, binary.LittleEndian, uprobeEntry.config)

		// filter_map data
		selBuff := uprobeEntry.selectors.Buffer()

		mapLoad := []*program.MapLoad{
			{
				Index: uint32(index),
				Name:  "config_map",
				Load: func(m *ebpf.Map, _ string, index uint32) error {
					return m.Update(index, configData.Bytes()[:], ebpf.UpdateAny)
				},
			},
			{
				Index: uint32(index),
				Name:  "filter_map",
				Load: func(m *ebpf.Map, _ string, index uint32) error {
					return m.Update(index, selBuff[:], ebpf.UpdateAny)
				},
			},
		}
		load.MapLoad = append(load.MapLoad, mapLoad...)

		attach, ok := data.Attach[uprobeEntry.path]
		if !ok {
			attach = &program.MultiUprobeAttachSymbolsCookies{}
		}

		attach.Symbols = append(attach.Symbols, uprobeEntry.symbol)
		attach.Cookies = append(attach.Cookies, uint64(index))

		data.Attach[uprobeEntry.path] = attach
	}

	load.SetAttachData(data)

	if err := program.LoadMultiUprobeProgram(args.BPFDir, args.Load, args.Verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic uprobe sensor: %s -> %s", load.Name, load.Attach)
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
			len(s.MatchActions) > 0 ||
			len(s.MatchReturnArgs) > 0 ||
			len(s.MatchNamespaces) > 0 ||
			len(s.MatchNamespaceChanges) > 0 ||
			len(s.MatchCapabilities) > 0 ||
			len(s.MatchCapabilityChanges) > 0 {
			return fmt.Errorf("Only matchPIDs selector is supported")
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
	policyName string,
	namespace string,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var ids []idtable.EntryID
	var err error

	options, err := getSpecOptions(spec.Options)
	if err != nil {
		return nil, fmt.Errorf("failed to set options: %s", err)
	}

	in := addUprobeIn{
		sensorPath: name,
		policyName: policyName,

		// use multi kprobe only if:
		// - it's not disabled by spec option
		// - there's support detected
		useMulti: !options.DisableUprobeMulti && bpf.HasUprobeMulti(),
	}

	for _, uprobe := range spec.UProbes {
		ids, err = addUprobe(&uprobe, ids, &in)
		if err != nil {
			return nil, err
		}
	}

	if in.useMulti {
		progs, maps, err = createMultiUprobeSensor(name, ids, policyName)
	} else {
		progs, maps, err = createSingleUprobeSensor(ids)
	}

	if err != nil {
		return nil, err
	}

	return &sensors.Sensor{
		Name:      name,
		Progs:     progs,
		Maps:      maps,
		Policy:    policyName,
		Namespace: namespace,
	}, nil
}

func addUprobe(spec *v1alpha1.UProbeSpec, ids []idtable.EntryID, in *addUprobeIn) ([]idtable.EntryID, error) {
	var args []v1alpha1.KProbeArg

	if err := isValidUprobeSelectors(spec.Selectors); err != nil {
		return nil, err
	}

	// Parse Filters into kernel filter logic
	uprobeSelectorState, err := selectors.InitKernelSelectorState(spec.Selectors, args, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	msgField, err := getPolicyMessage(spec.Message)
	if errors.Is(err, ErrMsgSyntaxShort) || errors.Is(err, ErrMsgSyntaxEscape) {
		return nil, err
	} else if errors.Is(err, ErrMsgSyntaxLong) {
		logger.GetLogger().WithField("policy-name", in.policyName).
			Warnf("TracingPolicy 'message' field too long, truncated to %d characters", TpMaxMessageLen)
	}

	var (
		argTypes [api.EventConfigMaxArgs]int32
		argMeta  [api.EventConfigMaxArgs]uint32
		argSet   [api.EventConfigMaxArgs]bool

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
			return nil, fmt.Errorf("Error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index))
		}
		argTypes[a.Index] = int32(argType)
		argMeta[a.Index] = uint32(argMValue)
		argSet[a.Index] = true

		argPrinters = append(argPrinters, argPrinter{index: i, ty: argType})
	}

	// Mark remaining arguments as 'nops' the kernel side will skip
	// copying 'nop' args.
	for i, a := range argSet {
		if !a {
			argTypes[i] = gt.GenericNopType
			argMeta[i] = 0
		}
	}

	for _, sym := range spec.Symbols {
		config := &api.EventConfig{
			Arg:  argTypes,
			ArgM: argMeta,
		}

		uprobeEntry := &genericUprobe{
			tableId:     idtable.UninitializedEntryID,
			config:      config,
			path:        spec.Path,
			symbol:      sym,
			selectors:   uprobeSelectorState,
			policyName:  in.policyName,
			message:     msgField,
			argPrinters: argPrinters,
			tags:        tagsField,
		}

		uprobeTable.AddEntry(uprobeEntry)
		id := uprobeEntry.tableId

		if in.useMulti {
			uprobeEntry.pinPathPrefix = multiUprobePinPath(in.sensorPath)
		} else {
			uprobeEntry.pinPathPrefix = sensors.PathJoin(in.sensorPath, fmt.Sprintf("gup-%d", id.ID))
		}

		config.FuncId = uint32(id.ID)

		ids = append(ids, id)
	}

	return ids, nil
}

func multiUprobePinPath(sensorPath string) string {
	return sensors.PathJoin(sensorPath, "multi_kprobe")
}

func createMultiUprobeSensor(sensorPath string, multiIDs []idtable.EntryID, policyName string) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	loadProgName := "bpf_multi_uprobe_v61.o"

	pinPath := multiUprobePinPath(sensorPath)

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("uprobe_multi (%d functions)", len(multiIDs)),
		"uprobe.multi/generic_uprobe",
		pinPath,
		"generic_uprobe").
		SetLoaderData(multiIDs).
		SetPolicy(policyName)

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)

	maps = append(maps, configMap, tailCalls, filterMap)
	maps = append(maps, program.MapUser(base.ExecveMap.Name, load))

	filterMap.SetMaxEntries(len(multiIDs))
	configMap.SetMaxEntries(len(multiIDs))
	return progs, maps, nil
}

func createSingleUprobeSensor(ids []idtable.EntryID) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	for _, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		progs, maps = createUprobeSensorFromEntry(uprobeEntry, progs, maps)
	}

	return progs, maps, nil
}

func createUprobeSensorFromEntry(uprobeEntry *genericUprobe,
	progs []*program.Program, maps []*program.Map) ([]*program.Program, []*program.Map) {

	loadProgName := "bpf_generic_uprobe.o"
	if kernels.EnableV61Progs() {
		loadProgName = "bpf_generic_uprobe_v61.o"
	} else if kernels.EnableLargeProgs() {
		loadProgName = "bpf_generic_uprobe_v53.o"
	}

	attachData := &program.UprobeAttachData{
		Path:   uprobeEntry.path,
		Symbol: uprobeEntry.symbol,
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

	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	tailCalls := program.MapBuilderProgram("uprobe_calls", load)
	filterMap := program.MapBuilderProgram("filter_map", load)
	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, configMap, tailCalls, filterMap, selMatchBinariesMap)
	maps = append(maps, program.MapUser(base.ExecveMap.Name, load))
	return progs, maps
}
