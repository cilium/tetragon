// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path"
	"path/filepath"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
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
}

func (g *genericUprobe) SetID(id idtable.EntryID) {
	g.tableId = id
}

func init() {
	uprobe := &observerUprobeSensor{
		name: "uprobe sensor",
	}
	sensors.RegisterProbeType("generic_uprobe", uprobe)
	sensors.RegisterPolicyHandlerAtInit(uprobe.name, uprobe)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_UPROBE, handleGenericUprobe)
}

func genericUprobeTableGet(id idtable.EntryID) (*genericUprobe, error) {
	if entry, err := uprobeTable.GetEntry(id); err != nil {
		return nil, fmt.Errorf("getting entry from uprobeTable failed with: %w", err)
	} else if val, ok := entry.(*genericUprobe); !ok {
		return nil, fmt.Errorf("getting entry from uprobeTable failed with: got invalid type: %T (%v)", entry, entry)
	} else {
		return val, nil
	}
}

func handleGenericUprobe(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	uprobeEntry, err := genericUprobeTableGet(idtable.EntryID{ID: int(m.Id)})
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to match id:%d", m.Id)
		return nil, fmt.Errorf("Failed to match id")
	}

	unix := &tracing.MsgGenericUprobeUnix{}
	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Path = uprobeEntry.path
	unix.Symbol = uprobeEntry.symbol

	return []observer.Event{unix}, err
}

func (k *observerUprobeSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	load := args.Load

	uprobeEntry, ok := load.LoaderData.(*genericUprobe)
	if !ok {
		return fmt.Errorf("invalid loadData type: expecting idtable.EntryID and got: %T (%v)", load.LoaderData, load.LoaderData)
	}

	// config_map data
	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, uprobeEntry.config)

	// filter_map data
	selBuff := uprobeEntry.selectors.Buffer()

	mapLoad := []*program.MapLoad{
		{
			Index: 0,
			Name:  "config_map",
			Load: func(m *ebpf.Map, index uint32) error {
				return m.Update(index, configData.Bytes()[:], ebpf.UpdateAny)
			},
		},
		{
			Index: 0,
			Name:  "filter_map",
			Load: func(m *ebpf.Map, index uint32) error {
				return m.Update(index, selBuff[:], ebpf.UpdateAny)
			},
		},
		{
			Index: 0,
			Name:  "sel_names_map",
			Load: func(outerMap *ebpf.Map, index uint32) error {
				return populateBinariesMaps(uprobeEntry.selectors, uprobeEntry.pinPathPrefix, outerMap)
			},
		},
	}

	load.MapLoad = append(load.MapLoad, mapLoad...)

	sensors.AllPrograms = append(sensors.AllPrograms, load)

	if err := program.LoadUprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose); err != nil {
		return err
	}

	m, err := ebpf.LoadPinnedMap(filepath.Join(args.MapDir, base.NamesMap.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	for i, path := range uprobeEntry.selectors.GetNewBinaryMappings() {
		writeBinaryMap(m, i, path)
	}

	logger.GetLogger().WithField("flags", flagsString(uprobeEntry.config.Flags)).
		Infof("Loaded generic uprobe program: %s -> %s [%s]", args.Load.Name, uprobeEntry.path, uprobeEntry.symbol)
	return nil
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

func createGenericUprobeSensor(
	name string,
	uprobes []v1alpha1.UProbeSpec,
	policyName string,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map

	sensorPath := name

	loadProgName := "bpf_generic_uprobe.o"
	if kernels.EnableV60Progs() {
		loadProgName = "bpf_generic_uprobe_v60.o"
	} else if kernels.EnableLargeProgs() {
		loadProgName = "bpf_generic_uprobe_v53.o"
	}

	for i := range uprobes {
		spec := &uprobes[i]
		config := &api.EventConfig{}

		var args []v1alpha1.KProbeArg

		if err := isValidUprobeSelectors(spec.Selectors); err != nil {
			return nil, err
		}

		// Parse Filters into kernel filter logic
		uprobeSelectorState, err := selectors.InitKernelSelectorState(spec.Selectors, args, nil)
		if err != nil {
			return nil, err
		}

		uprobeEntry := &genericUprobe{
			tableId:    idtable.UninitializedEntryID,
			config:     config,
			path:       spec.Path,
			symbol:     spec.Symbol,
			selectors:  uprobeSelectorState,
			policyName: policyName,
		}

		uprobeTable.AddEntry(uprobeEntry)
		id := uprobeEntry.tableId.ID

		uprobeEntry.pinPathPrefix = sensors.PathJoin(sensorPath, fmt.Sprintf("%d", id))
		config.FuncId = uint32(id)

		if selectors.HasEarlyBinaryFilter(spec.Selectors) {
			config.Flags |= flagsEarlyFilter
		}

		pinPath := uprobeEntry.pinPathPrefix
		pinProg := sensors.PathJoin(pinPath, "prog")

		attachData := &program.UprobeAttachData{
			Path:   spec.Path,
			Symbol: spec.Symbol,
		}

		load := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgName),
			"",
			"uprobe/generic_uprobe",
			pinProg,
			"generic_uprobe").
			SetAttachData(attachData).
			SetLoaderData(uprobeEntry)

		progs = append(progs, load)

		configMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "config_map"), load)
		tailCalls := program.MapBuilderPin("uprobe_calls", sensors.PathJoin(pinPath, "up_calls"), load)
		filterMap := program.MapBuilderPin("filter_map", sensors.PathJoin(pinPath, "filter_map"), load)
		selNamesMap := program.MapBuilderPin("sel_names_map", sensors.PathJoin(pinPath, "sel_names_map"), load)
		maps = append(maps, configMap, tailCalls, filterMap, selNamesMap)
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
	}, nil
}

func (k *observerUprobeSensor) PolicyHandler(
	p tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := p.TpSpec()

	if len(spec.UProbes) == 0 {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("uprobe sensor does not implement policy filtering")
	}

	name := fmt.Sprintf("gup-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
	policyName := p.TpName()
	return createGenericUprobeSensor(name, spec.UProbes, policyName)
}
