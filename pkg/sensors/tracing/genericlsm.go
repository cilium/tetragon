// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strings"

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
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type observerLsmSensor struct {
	name string
}

func init() {
	lsm := &observerLsmSensor{
		name: "lsm sensor",
	}
	sensors.RegisterProbeType("generic_lsm", lsm)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_LSM, handleGenericLsm)
}

var (
	// genericLsmTable is a global table that maintains information for
	// generic LSM hooks
	genericLsmTable idtable.Table
)

type genericLsm struct {
	tableId       idtable.EntryID
	pinPathPrefix string
	config        *api.EventConfig
	hook          string
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

func (g *genericLsm) SetID(id idtable.EntryID) {
	g.tableId = id
}

func genericLsmTableGet(id idtable.EntryID) (*genericLsm, error) {
	entry, err := genericLsmTable.GetEntry(id)
	if err != nil {
		return nil, fmt.Errorf("getting entry from genericLsmTable failed with: %w", err)
	}
	val, ok := entry.(*genericLsm)
	if !ok {
		return nil, fmt.Errorf("getting entry from genericLsmTable failed with: got invalid type: %T (%v)", entry, entry)
	}
	return val, nil
}

func (k *observerLsmSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if id, ok := args.Load.LoaderData.(idtable.EntryID); ok {
		gl, err := genericLsmTableGet(id)
		if err != nil {
			return err
		}
		args.Load.MapLoad = append(args.Load.MapLoad, selectorsMaploads(gl.selectors, 0)...)
		var configData bytes.Buffer
		binary.Write(&configData, binary.LittleEndian, gl.config)
		config := &program.MapLoad{
			Index: 0,
			Name:  "config_map",
			Load: func(m *ebpf.Map, _ string, index uint32) error {
				return m.Update(index, configData.Bytes()[:], ebpf.UpdateAny)
			},
		}
		args.Load.MapLoad = append(args.Load.MapLoad, config)

		if err := program.LoadLSMProgram(args.BPFDir, args.Load, args.Verbose); err == nil {
			logger.GetLogger().Infof("Loaded generic LSM program: %s -> %s", args.Load.Name, args.Load.Attach)
		} else {
			return err
		}
	} else {
		return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
			args.Load.LoaderData, args.Load.LoaderData)
	}
	return nil
}

func handleGenericLsm(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	gl, err := genericLsmTableGet(idtable.EntryID{ID: int(m.FuncId)})
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to match id:%d", m.FuncId)
		return nil, fmt.Errorf("Failed to match id")
	}

	unix := &tracing.MsgGenericLsmUnix{}
	unix.Msg = &m
	unix.Hook = gl.hook
	unix.PolicyName = gl.policyName
	unix.Message = gl.message
	unix.Tags = gl.tags

	printers := gl.argPrinters

	// Get argument objects for specific printers/types
	for _, a := range printers {
		arg := getArg(r, a)
		// nop or unknown type (already logged)
		if arg == nil {
			continue
		}
		unix.Args = append(unix.Args, arg)
	}

	return []observer.Event{unix}, err
}

func isValidLsmSelectors(selectors []v1alpha1.KProbeSelector) error {
	for _, s := range selectors {
		if len(s.MatchReturnArgs) > 0 {
			return fmt.Errorf("MatchReturnArgs selector is not supported")
		}
		if len(s.MatchActions) > 0 {
			for _, a := range s.MatchActions {
				switch strings.ToLower(a.Action) {
				case "sigkill":
				case "signal":
				case "nopost":
				case "override":
					continue
				case "post":
					if a.KernelStackTrace || a.UserStackTrace {
						return fmt.Errorf("Stacktrace actions are not supported")
					}
				default:
					return fmt.Errorf("%s action is not supported", a.Action)
				}
			}
		}
	}
	return nil
}

type addLsmIn struct {
	sensorPath string
	policyName string
	policyID   policyfilter.PolicyID
	selMaps    *selectors.KernelSelectorMaps
}

func addLsm(f *v1alpha1.LsmHookSpec, in *addLsmIn) (id idtable.EntryID, err error) {
	var argSigPrinters []argPrinter
	var argsBTFSet [api.MaxArgsSupported]bool

	errFn := func(err error) (idtable.EntryID, error) {
		return idtable.UninitializedEntryID, err
	}

	if err := isValidLsmSelectors(f.Selectors); err != nil {
		return errFn(err)
	}

	config := &api.EventConfig{}
	config.PolicyID = uint32(in.policyID)

	msgField, err := getPolicyMessage(f.Message)
	if errors.Is(err, ErrMsgSyntaxShort) || errors.Is(err, ErrMsgSyntaxEscape) {
		return errFn(fmt.Errorf("Error: '%v'", err))
	} else if errors.Is(err, ErrMsgSyntaxLong) {
		logger.GetLogger().WithField("policy-name", in.policyName).Warnf("TracingPolicy 'message' field too long, truncated to %d characters", TpMaxMessageLen)
	}

	tagsField, err := getPolicyTags(f.Tags)
	if err != nil {
		return errFn(fmt.Errorf("Error: '%v'", err))
	}

	// Parse Arguments
	for j, a := range f.Args {
		argType := gt.GenericTypeFromString(a.Type)
		if argType == gt.GenericInvalidType {
			return errFn(fmt.Errorf("Arg(%d) type '%s' unsupported", j, a.Type))
		}
		if a.MaxData {
			if argType != gt.GenericCharBuffer {
				logger.GetLogger().Warnf("maxData flag is ignored (supported for char_buf type)")
			}
			if !kernels.EnableLargeProgs() {
				logger.GetLogger().Warnf("maxData flag is ignored (supported from large programs)")
			}
		}
		argMValue, err := getMetaValue(&a)
		if err != nil {
			return errFn(err)
		}
		if a.Index > 4 {
			return errFn(fmt.Errorf("Error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index)))
		}
		config.Arg[a.Index] = int32(argType)
		config.ArgM[a.Index] = uint32(argMValue)

		argsBTFSet[a.Index] = true
		argP := argPrinter{index: j, ty: argType, maxData: a.MaxData, label: a.Label}
		argSigPrinters = append(argSigPrinters, argP)
	}

	config.ArgReturn = int32(0)
	config.ArgReturnCopy = int32(0)

	// Mark remaining arguments as 'nops' the kernel side will skip
	// copying 'nop' args.
	for j, a := range argsBTFSet {
		if !a {
			if j != api.ReturnArgIndex {
				config.Arg[j] = gt.GenericNopType
				config.ArgM[j] = 0
			}
		}
	}

	config.Syscall = 0

	// create a new entry on the table, and pass its id to BPF-side
	// so that we can do the matching at event-generation time
	lsmEntry := genericLsm{
		config:      config,
		argPrinters: argSigPrinters,
		hook:        f.Hook,
		tableId:     idtable.UninitializedEntryID,
		policyName:  in.policyName,
		message:     msgField,
		tags:        tagsField,
	}

	// Parse Filters into kernel filter logic
	lsmEntry.selectors, err = selectors.InitKernelSelectorState(f.Selectors, f.Args, nil, nil, in.selMaps)
	if err != nil {
		return errFn(err)
	}

	genericLsmTable.AddEntry(&lsmEntry)
	config.FuncId = uint32(lsmEntry.tableId.ID)

	lsmEntry.pinPathPrefix = sensors.PathJoin(in.sensorPath, fmt.Sprintf("glsm-%d", lsmEntry.tableId.ID))

	logger.GetLogger().
		WithField("hook", lsmEntry.hook).
		Infof("Added lsm Hook")

	return lsmEntry.tableId, nil
}

func createGenericLsmSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	policyID policyfilter.PolicyID,
	policyName string,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var ids []idtable.EntryID
	var selMaps *selectors.KernelSelectorMaps
	var err error

	if !bpf.HasLSMPrograms() || !kernels.EnableLargeProgs() {
		return nil, fmt.Errorf("Does you kernel support the bpf LSM? You can enable LSM BPF by modifying" +
			"the GRUB configuration /etc/default/grub with GRUB_CMDLINE_LINUX=\"lsm=bpf\"")
	}

	lsmHooks := spec.LsmHooks

	in := addLsmIn{
		sensorPath: name,
		policyID:   policyID,
		policyName: policyName,
		selMaps:    selMaps,
	}

	for _, hook := range lsmHooks {
		id, err := addLsm(&hook, &in)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	for _, id := range ids {
		gl, err := genericLsmTableGet(id)
		if err != nil {
			return nil, err
		}
		progs, maps = createLsmSensorFromEntry(gl, progs, maps)
	}

	if err != nil {
		return nil, err
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
		DestroyHook: func() error {
			var errs error
			for _, id := range ids {
				_, err := genericLsmTable.RemoveEntry(id)
				if err != nil {
					errs = errors.Join(errs, err)
				}
			}
			return errs
		},
		Policy: policyName,
	}, nil
}

func createLsmSensorFromEntry(lsmEntry *genericLsm,
	progs []*program.Program, maps []*program.Map) ([]*program.Program, []*program.Map) {

	loadProgName := "bpf_generic_lsm.o"
	if kernels.EnableV61Progs() {
		loadProgName = "bpf_generic_lsm_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		loadProgName = "bpf_generic_lsm_v511.o"
	}

	pinPath := lsmEntry.pinPathPrefix
	pinProg := sensors.PathJoin(pinPath, fmt.Sprintf("%s_prog", lsmEntry.hook))

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		lsmEntry.hook,
		"lsm/generic_lsm",
		pinProg,
		"generic_lsm").
		SetLoaderData(lsmEntry.tableId)
	progs = append(progs, load)

	configMap := program.MapBuilderProgram("config_map", load)
	maps = append(maps, configMap)

	tailCalls := program.MapBuilderProgram("lsm_calls", load)
	maps = append(maps, tailCalls)

	load.SetTailCall("lsm", tailCalls)

	filterMap := program.MapBuilderProgram("filter_map", load)
	maps = append(maps, filterMap)

	maps = append(maps, filterMapsForLsm(load, lsmEntry)...)

	callHeap := program.MapBuilderProgram("process_call_heap", load)
	maps = append(maps, callHeap)

	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, selMatchBinariesMap)

	matchBinariesPaths := program.MapBuilderProgram("tg_mb_paths", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		matchBinariesPaths.SetInnerMaxEntries(lsmEntry.selectors.MatchBinariesPathsMaxEntries())
	}
	maps = append(maps, matchBinariesPaths)

	logger.GetLogger().
		Infof("Added generic lsm sensor: %s -> %s", load.Name, load.Attach)
	return progs, maps
}

func filterMapsForLsm(load *program.Program, lsmEntry *genericLsm) []*program.Map {
	var maps []*program.Map

	argFilterMaps := program.MapBuilderProgram("argfilter_maps", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := lsmEntry.selectors.ValueMapsMaxEntries()
		argFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, argFilterMaps)

	addr4FilterMaps := program.MapBuilderProgram("addr4lpm_maps", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := lsmEntry.selectors.Addr4MapsMaxEntries()
		addr4FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, addr4FilterMaps)

	addr6FilterMaps := program.MapBuilderProgram("addr6lpm_maps", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := lsmEntry.selectors.Addr6MapsMaxEntries()
		addr6FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, addr6FilterMaps)

	var stringFilterMap [selectors.StringMapsNumSubMaps]*program.Map
	numSubMaps := selectors.StringMapsNumSubMaps
	if !kernels.MinKernelVersion("5.11") {
		numSubMaps = selectors.StringMapsNumSubMapsSmall
	}

	for string_map_index := 0; string_map_index < numSubMaps; string_map_index++ {
		stringFilterMap[string_map_index] = program.MapBuilderProgram(fmt.Sprintf("string_maps_%d", string_map_index), load)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := lsmEntry.selectors.StringMapsMaxEntries(string_map_index)
			stringFilterMap[string_map_index].SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, stringFilterMap[string_map_index])
	}

	stringPrefixFilterMaps := program.MapBuilderProgram("string_prefix_maps", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := lsmEntry.selectors.StringPrefixMapsMaxEntries()
		stringPrefixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, stringPrefixFilterMaps)

	stringPostfixFilterMaps := program.MapBuilderProgram("string_postfix_maps", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := lsmEntry.selectors.StringPostfixMapsMaxEntries()
		stringPostfixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, stringPostfixFilterMaps)

	return maps
}
