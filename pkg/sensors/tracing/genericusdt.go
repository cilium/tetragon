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

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
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
	}

	for _, usdt := range spec.Usdts {
		ids, err = addUsdt(&usdt, &in, ids)
		if err != nil {
			return nil, err
		}
	}

	progs, maps, err = createSingleUsdtSensor(ids)
	if err != nil {
		return nil, err
	}

	maps = append(maps, program.MapUserFrom(base.ExecveMap))

	return &sensors.Sensor{
		Name:      name,
		Progs:     progs,
		Maps:      maps,
		Policy:    polInfo.name,
		Namespace: polInfo.namespace,
	}, nil
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

		usdtEntry := &genericUsdt{
			tableId:     idtable.UninitializedEntryID,
			config:      config,
			path:        spec.Path,
			target:      target,
			policyName:  in.policyName,
			argPrinters: argPrinters,
			tags:        tagsField,
			message:     msgField,
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
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}

func loadSingleUsdtSensor(usdtEntry *genericUsdt, args sensors.LoadProbeArgs) error {
	load := args.Load

	// config_map data
	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, usdtEntry.config)

	mapLoad := []*program.MapLoad{
		{
			Name: "config_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(uint32(0), configData.Bytes()[:], ebpf.UpdateAny)
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
