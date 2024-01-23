// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	gt "github.com/cilium/tetragon/pkg/generictypes"
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
	// message field of the Tracing Policy
	message string
	// argument data printers
	argPrinters []argPrinter
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
	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Tid = m.Tid
	unix.Path = uprobeEntry.path
	unix.Symbol = uprobeEntry.symbol
	unix.PolicyName = uprobeEntry.policyName
	unix.Message = uprobeEntry.message

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
	}

	load.MapLoad = append(load.MapLoad, mapLoad...)

	sensors.AllPrograms = append(sensors.AllPrograms, load)

	if err := program.LoadUprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose); err != nil {
		return err
	}

	logger.GetLogger().Infof("Loaded generic uprobe program: %s -> %s [%s]", args.Load.Name, uprobeEntry.path, uprobeEntry.symbol)
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
	if kernels.EnableV61Progs() {
		loadProgName = "bpf_generic_uprobe_v61.o"
	} else if kernels.EnableLargeProgs() {
		loadProgName = "bpf_generic_uprobe_v53.o"
	}

	for _, spec := range uprobes {
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
			logger.GetLogger().WithField("policy-name", policyName).Warnf("TracingPolicy 'message' field too long, truncated to %d characters", TpMaxMessageLen)
		}

		var (
			argTypes [api.EventConfigMaxArgs]int32
			argMeta  [api.EventConfigMaxArgs]uint32
			argSet   [api.EventConfigMaxArgs]bool

			argPrinters []argPrinter
		)

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
				policyName:  policyName,
				message:     msgField,
				argPrinters: argPrinters,
			}

			uprobeTable.AddEntry(uprobeEntry)
			id := uprobeEntry.tableId.ID

			uprobeEntry.pinPathPrefix = sensors.PathJoin(sensorPath, fmt.Sprintf("%d", id))
			config.FuncId = uint32(id)

			pinPath := uprobeEntry.pinPathPrefix
			pinProg := sensors.PathJoin(pinPath, "prog")

			attachData := &program.UprobeAttachData{
				Path:   spec.Path,
				Symbol: sym,
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
			selMatchBinariesMap := program.MapBuilderPin("tg_mb_sel_opts", sensors.PathJoin(pinPath, "tg_mb_sel_opts"), load)
			maps = append(maps, configMap, tailCalls, filterMap, selMatchBinariesMap)
		}
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
