// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/enforcermetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/network"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/syscallinfo"
	"github.com/cilium/tetragon/pkg/tracepoint"
	"github.com/sirupsen/logrus"

	gt "github.com/cilium/tetragon/pkg/generictypes"
)

const (
	// nolint We probably want to keep this even though it's unused at the moment
	// NB: this should match the size of ->args[] of the output message
	genericTP_OutputSize = 9000
)

var (
	// Tracepoint information (genericTracepoint) is needed at load time
	// and at the time we process the perf event from bpf-side. We keep
	// this information on a table index by a (unique) tracepoint id.
	genericTracepointTable = tracepointTable{}

	tracepointLog logrus.FieldLogger
)

type observerTracepointSensor struct {
	name string
}

func init() {
	tp := &observerTracepointSensor{
		name: "tracepoint sensor",
	}
	sensors.RegisterProbeType("generic_tracepoint", tp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_TRACEPOINT, handleGenericTracepoint)
}

// genericTracepoint is the internal representation of a tracepoint
type genericTracepoint struct {
	Info *tracepoint.Tracepoint
	args []genericTracepointArg

	Spec     *v1alpha1.TracepointSpec
	policyID policyfilter.PolicyID

	// index to access this on genericTracepointTable
	tableIdx int

	// for tracepoints that have a GetUrl or DnsLookup action, we store the table of arguments.
	actionArgs idtable.Table

	pinPathPrefix string

	// policyName is the name of the policy that this tracepoint belongs to
	policyName string

	// message field of the Tracing Policy
	message string

	// tags field of the Tracing Policy
	tags []string

	// parsed kernel selector state
	selectors *selectors.KernelSelectorState

	// custom event handler
	customHandler eventhandler.Handler
}

// genericTracepointArg is the internal representation of an output value of a
// generic tracepoint.
type genericTracepointArg struct {
	CtxOffset int    // offset within tracepoint ctx
	ArgIdx    uint32 // index in genericTracepoint.args
	TpIdx     int    // index in the tracepoint arguments

	// Meta field: the user defines the meta argument in terms of the
	// tracepoint arguments (MetaTp), but we have to translate it to
	// the ebpf-side arguments (MetaArgIndex).
	// MetaTp
	//  0  -> no metadata information
	//  >0 -> metadata are in the MetaTp of the tracepoint args (1-based)
	//  -1 -> metadata are in retprobe
	MetaTp  int
	MetaArg int

	// this is true if the argument is need to be read, but it's not going
	// to be part of the output. This is needed for arguments that hold
	// metadata but are not part of the output.
	nopTy bool

	// format of the field
	format *tracepoint.FieldFormat

	// bpf generic type
	genericTypeId int

	// user type overload
	userType string
}

// tracepointTable is, for now, an array.
type tracepointTable struct {
	mu  sync.Mutex
	arr []*genericTracepoint
}

// addTracepoint adds a tracepoint to the table, and sets its .tableIdx field
// to be the index to retrieve it from the table.
func (t *tracepointTable) addTracepoint(tp *genericTracepoint) {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx := len(t.arr)
	t.arr = append(t.arr, tp)
	tp.tableIdx = idx
}

// getTracepoint retrieves a tracepoint from the table using its id
func (t *tracepointTable) getTracepoint(idx int) (*genericTracepoint, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx < len(t.arr) {
		return t.arr[idx], nil
	}
	return nil, fmt.Errorf("tracepoint table: invalid id:%d (len=%d)", idx, len(t.arr))
}

func (out *genericTracepointArg) String() string {
	return fmt.Sprintf("genericTracepointArg{CtxOffset: %d format: %+v}", out.CtxOffset, out.format)
}

func (out *genericTracepointArg) setGenericTypeId() (int, error) {
	ret, err := out.getGenericTypeId()
	out.genericTypeId = ret
	return ret, err
}

// getGenericTypeId: returns the generic type Id of a tracepoint argument
// if such an id cannot be termined, it returns an GenericInvalidType and an error
func (out *genericTracepointArg) getGenericTypeId() (int, error) {

	if out.userType != "" && out.userType != "auto" {
		if out.userType == "const_buf" {
			// const_buf type depends on the .format.field.Type to decode the result, so
			// disallow it.
			return gt.GenericInvalidType, errors.New("const_buf type cannot be user-defined")
		}
		return gt.GenericTypeFromString(out.userType), nil
	}

	if out.format == nil {
		return gt.GenericInvalidType, errors.New("format is nil")
	}

	if out.format.Field == nil {
		err := out.format.ParseField()
		if err != nil {
			return gt.GenericInvalidType, fmt.Errorf("failed to parse field: %w", err)
		}
	}

	switch ty := out.format.Field.Type.(type) {
	case tracepoint.IntTy:
		if out.format.Size == 4 && out.format.IsSigned {
			return gt.GenericS32Type, nil
		} else if out.format.Size == 4 && !out.format.IsSigned {
			return gt.GenericU32Type, nil
		} else if out.format.Size == 8 && out.format.IsSigned {
			return gt.GenericS64Type, nil
		} else if out.format.Size == 8 && !out.format.IsSigned {
			return gt.GenericU64Type, nil
		}
	case tracepoint.PointerTy:
		// char *
		intTy, ok := ty.Ty.(tracepoint.IntTy)
		if !ok {
			return gt.GenericInvalidType, fmt.Errorf("cannot handle pointer type to %T", ty)
		}
		if intTy.Base == tracepoint.IntTyChar {
			// NB: there is no way to determine if this is a string
			// or a buffer without user information or something we
			// build manually ourselves. For now, we only deal with
			// buffers and expect a metadata argument.
			if out.MetaTp == 0 {
				return gt.GenericInvalidType, errors.New("no metadata field for buffer")
			}
			return gt.GenericCharBuffer, nil
		}

	// NB: we handle array types as constant buffers for now. We copy the
	// data to user-space, and decode them there.
	case tracepoint.ArrayTy:
		nbytes, err := ty.NBytes()
		if err != nil {
			return gt.GenericInvalidType, fmt.Errorf("failed to get size of array type %w", err)
		}
		if out.MetaArg == 0 {
			// set MetaArg equal to the number of bytes we need to copy
			out.MetaArg = nbytes
		}
		return gt.GenericConstBuffer, nil

	case tracepoint.SizeTy:
		return gt.GenericSizeType, nil
	}

	return gt.GenericInvalidType, fmt.Errorf("Unknown type: %T", out.format.Field.Type)
}

func buildGenericTracepointArgs(info *tracepoint.Tracepoint, specArgs []v1alpha1.KProbeArg) ([]genericTracepointArg, error) {
	ret := make([]genericTracepointArg, 0, len(specArgs))
	nfields := uint32(len(info.Format.Fields))

	for argIdx := range specArgs {
		specArg := &specArgs[argIdx]
		if specArg.Index >= nfields {
			return nil, fmt.Errorf("tracepoint %s/%s has %d fields but field %d was requested", info.Subsys, info.Event, nfields, specArg.Index)
		}
		field := info.Format.Fields[specArg.Index]
		ret = append(ret, genericTracepointArg{
			CtxOffset:     int(field.Offset),
			ArgIdx:        uint32(argIdx),
			TpIdx:         int(specArg.Index),
			MetaTp:        getTracepointMetaValue(specArg),
			nopTy:         false,
			format:        &field,
			genericTypeId: gt.GenericInvalidType,
			userType:      specArg.Type,
		})
	}

	// getOrAppendMeta is a helper function for meta arguments now that we
	// have the configured arguments, we also need to configure meta
	// arguments. Some of them will exist already, but others we will have
	// to create with a nop type so that they will be fetched, but not be
	// part of the output
	getOrAppendMeta := func(metaTp int) (*genericTracepointArg, error) {
		tpIdx := metaTp - 1
		for i := range ret {
			if ret[i].TpIdx == tpIdx {
				return &ret[i], nil
			}
		}

		if tpIdx >= int(nfields) {
			return nil, fmt.Errorf("tracepoint %s/%s has %d fields but field %d was requested in a metadata argument", info.Subsys, info.Event, len(info.Format.Fields), tpIdx)
		}
		field := info.Format.Fields[tpIdx]
		argIdx := uint32(len(ret))
		ret = append(ret, genericTracepointArg{
			CtxOffset:     int(field.Offset),
			ArgIdx:        argIdx,
			TpIdx:         tpIdx,
			MetaTp:        0,
			MetaArg:       0,
			nopTy:         true,
			format:        &field,
			genericTypeId: gt.GenericInvalidType,
		})
		return &ret[argIdx], nil
	}

	for idx := 0; idx < len(ret); idx++ {
		meta := ret[idx].MetaTp
		if meta == 0 || meta == -1 {
			ret[idx].MetaArg = meta
			continue
		}
		a, err := getOrAppendMeta(meta)
		if err != nil {
			return nil, err
		}
		ret[idx].MetaArg = int(a.ArgIdx) + 1
	}
	return ret, nil
}

// createGenericTracepoint creates the genericTracepoint information based on
// the user-provided configuration
func createGenericTracepoint(
	sensorName string,
	conf *v1alpha1.TracepointSpec,
	policyID policyfilter.PolicyID,
	policyName string,
	customHandler eventhandler.Handler,
) (*genericTracepoint, error) {
	if conf == nil {
		return nil, errors.New("failed creating generic tracepoint, conf is nil")
	}

	tp := tracepoint.Tracepoint{
		Subsys: conf.Subsystem,
		Event:  conf.Event,
	}

	msgField, err := getPolicyMessage(conf.Message)
	if errors.Is(err, ErrMsgSyntaxShort) || errors.Is(err, ErrMsgSyntaxEscape) {
		return nil, err
	} else if errors.Is(err, ErrMsgSyntaxLong) {
		logger.GetLogger().WithField("policy-name", policyName).Warnf("TracingPolicy 'message' field too long, truncated to %d characters", TpMaxMessageLen)
	}

	tagsField, err := getPolicyTags(conf.Tags)
	if err != nil {
		return nil, err
	}

	if err := tp.LoadFormat(); err != nil {
		return nil, fmt.Errorf("tracepoint %s/%s not supported: %w", tp.Subsys, tp.Event, err)
	}

	tpArgs, err := buildGenericTracepointArgs(&tp, conf.Args)
	if err != nil {
		return nil, err
	}

	ret := &genericTracepoint{
		Info:          &tp,
		Spec:          conf,
		args:          tpArgs,
		policyID:      policyID,
		policyName:    policyName,
		customHandler: customHandler,
		message:       msgField,
		tags:          tagsField,
	}

	genericTracepointTable.addTracepoint(ret)
	ret.pinPathPrefix = sensors.PathJoin(sensorName, fmt.Sprintf("gtp-%d", ret.tableIdx))
	return ret, nil
}

func tpValidateAndAdjustEnforcerAction(
	sensor *sensors.Sensor,
	tp *v1alpha1.TracepointSpec,
	tpID int,
	policyName string,
	spec *v1alpha1.TracingPolicySpec) error {

	registeredEnforcerMetrics := false
	for si := range tp.Selectors {
		sel := &tp.Selectors[si]
		for ai := range sel.MatchActions {
			act := &sel.MatchActions[ai]
			if act.Action == "NotifyEnforcer" {
				if len(spec.Enforcers) == 0 {
					return fmt.Errorf("NotifyEnforcer action specified, but spec contains no enforcers")
				}

				// EnforcerNotifyActionArgIndex already set, do nothing
				if act.EnforcerNotifyActionArgIndex != nil {
					continue
				}

				switch {
				case tp.Subsystem == "raw_syscalls" && tp.Event == "sys_enter":
					for i, arg := range tp.Args {
						// syscall id
						if arg.Index == 4 {
							val := uint32(i)
							act.EnforcerNotifyActionArgIndex = &val
						}
					}
					defaultABI, _ := syscallinfo.DefaultABI()
					enforcermetrics.RegisterInfo(policyName, uint32(tpID), func(arg uint32) string {
						syscallID := parseSyscall64Value(uint64(arg))
						sysName, _ := syscallinfo.GetSyscallName(syscallID.ABI, int(syscallID.ID))
						if sysName == "" {
							sysName = fmt.Sprintf("syscall-%d", syscallID.ID)
						}
						if syscallID.ABI != defaultABI {
							sysName = fmt.Sprintf("%s/%s", syscallID.ABI, sysName)
						}
						return sysName
					})
					registeredEnforcerMetrics = true
				default:
					enforcermetrics.RegisterInfo(policyName, uint32(tpID), func(_ uint32) string {
						return fmt.Sprintf("%s/%s", tp.Subsystem, tp.Event)
					})

				}
			}
		}
	}

	if registeredEnforcerMetrics {
		sensor.AddPostUnloadHook(func() error {
			enforcermetrics.UnregisterPolicy(policyName)
			return nil
		})
	}

	return nil
}

// createGenericTracepointSensor will create a sensor that can be loaded based on a generic tracepoint configuration
func createGenericTracepointSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	policyID policyfilter.PolicyID,
	policyName string,
	namespace string,
	customHandler eventhandler.Handler,
) (*sensors.Sensor, error) {
	confs := spec.Tracepoints
	lists := spec.Lists

	ret := &sensors.Sensor{
		Name:      name,
		Policy:    policyName,
		Namespace: namespace,
	}

	tracepoints := make([]*genericTracepoint, 0, len(confs))
	for i := range confs {
		tpSpec := &confs[i]
		err := tpValidateAndAdjustEnforcerAction(ret, tpSpec, i, policyName, spec)
		if err != nil {
			return nil, err
		}
		tp, err := createGenericTracepoint(name, tpSpec, policyID, policyName, customHandler)
		if err != nil {
			return nil, err
		}
		tracepoints = append(tracepoints, tp)
	}

	progName := "bpf_generic_tracepoint.o"
	if kernels.EnableV61Progs() {
		progName = "bpf_generic_tracepoint_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		progName = "bpf_generic_tracepoint_v511.o"
	} else if kernels.EnableLargeProgs() {
		progName = "bpf_generic_tracepoint_v53.o"
	}

	has := hasMaps{
		enforcer: len(spec.Enforcers) != 0,
	}

	maps := []*program.Map{}
	progs := make([]*program.Program, 0, len(tracepoints))
	for _, tp := range tracepoints {
		pinProg := sensors.PathJoin(fmt.Sprintf("%s:%s", tp.Info.Subsys, tp.Info.Event))
		attach := fmt.Sprintf("%s/%s", tp.Info.Subsys, tp.Info.Event)
		prog0 := program.Builder(
			path.Join(option.Config.HubbleLib, progName),
			attach,
			"tracepoint/generic_tracepoint",
			pinProg,
			"generic_tracepoint",
		).SetPolicy(policyName)

		err := tp.InitKernelSelectors(lists)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize tracepoint kernel selectors: %w", err)
		}

		has.fdInstall = selectorsHaveFDInstall(tp.Spec.Selectors)

		prog0.LoaderData = tp.tableIdx
		progs = append(progs, prog0)

		fdinstall := program.MapBuilderSensor("fdinstall_map", prog0)
		if has.fdInstall {
			fdinstall.SetMaxEntries(fdInstallMapMaxEntries)
		}
		maps = append(maps, fdinstall)

		tailCalls := program.MapBuilderProgram("tp_calls", prog0)
		maps = append(maps, tailCalls)

		filterMap := program.MapBuilderProgram("filter_map", prog0)
		maps = append(maps, filterMap)

		argFilterMaps := program.MapBuilderProgram("argfilter_maps", prog0)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := tp.selectors.ValueMapsMaxEntries()
			argFilterMaps.SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, argFilterMaps)

		addr4FilterMaps := program.MapBuilderProgram("addr4lpm_maps", prog0)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := tp.selectors.Addr4MapsMaxEntries()
			addr4FilterMaps.SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, addr4FilterMaps)

		addr6FilterMaps := program.MapBuilderProgram("addr6lpm_maps", prog0)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := tp.selectors.Addr6MapsMaxEntries()
			addr6FilterMaps.SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, addr6FilterMaps)

		numSubMaps := selectors.StringMapsNumSubMaps
		if !kernels.MinKernelVersion("5.11") {
			numSubMaps = selectors.StringMapsNumSubMapsSmall
		}
		for string_map_index := 0; string_map_index < numSubMaps; string_map_index++ {
			stringFilterMap := program.MapBuilderProgram(fmt.Sprintf("string_maps_%d", string_map_index), prog0)
			if !kernels.MinKernelVersion("5.9") {
				// Versions before 5.9 do not allow inner maps to have different sizes.
				// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
				maxEntries := tp.selectors.StringMapsMaxEntries(string_map_index)
				stringFilterMap.SetInnerMaxEntries(maxEntries)
			}
			maps = append(maps, stringFilterMap)
		}

		stringPrefixFilterMaps := program.MapBuilderProgram("string_prefix_maps", prog0)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := tp.selectors.StringPrefixMapsMaxEntries()
			stringPrefixFilterMaps.SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, stringPrefixFilterMaps)

		stringPostfixFilterMaps := program.MapBuilderProgram("string_postfix_maps", prog0)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := tp.selectors.StringPostfixMapsMaxEntries()
			stringPostfixFilterMaps.SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, stringPostfixFilterMaps)

		matchBinariesPaths := program.MapBuilderProgram("tg_mb_paths", prog0)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			matchBinariesPaths.SetInnerMaxEntries(tp.selectors.MatchBinariesPathsMaxEntries())
		}
		maps = append(maps, matchBinariesPaths)

		if has.enforcer {
			maps = append(maps, enforcerMapsUser(prog0)...)
		}

		if option.Config.EnableCgTrackerID {
			maps = append(maps, program.MapUser(cgtracker.MapName, prog0))
		}

		selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", prog0)
		maps = append(maps, selMatchBinariesMap)

		maps = append(maps, program.MapUser(base.ExecveMap.Name, prog0))
	}

	ret.Progs = progs
	ret.Maps = maps
	return ret, nil
}

func (tp *genericTracepoint) InitKernelSelectors(lists []v1alpha1.ListSpec) error {
	if tp.selectors != nil {
		return fmt.Errorf("InitKernelSelectors: selectors already initialized")
	}

	// rewrite arg index
	selArgs := make([]v1alpha1.KProbeArg, 0, len(tp.args))
	selSelectors := make([]v1alpha1.KProbeSelector, 0, len(tp.Spec.Selectors))
	for i := range tp.Spec.Selectors {
		origSel := &tp.Spec.Selectors[i]
		selSelectors = append(selSelectors, *origSel.DeepCopy())
	}

	for i := range tp.args {
		tpArg := &tp.args[i]
		ty, err := tpArg.setGenericTypeId()
		if err != nil {
			return fmt.Errorf("output argument %v unsupported: %w", tpArg, err)
		}
		selType, err := gt.GenericTypeToString(ty)
		if err != nil {
			return fmt.Errorf("output argument %v type not found: %w", tpArg, err)
		}

		// NB: this a selector argument, meant to be passed to InitKernelSelectors.
		// The only fields needed for the latter are Index and Type
		selArg := v1alpha1.KProbeArg{
			Index: tpArg.ArgIdx,
			Type:  selType,
		}
		selArgs = append(selArgs, selArg)

		// update selectors
		for j, s := range selSelectors {
			for k, match := range s.MatchArgs {
				if match.Index == uint32(tpArg.TpIdx) {
					selSelectors[j].MatchArgs[k].Index = uint32(tpArg.ArgIdx)
				}
			}
		}
	}

	selectors, err := selectors.InitKernelSelectorState(selSelectors, selArgs, &tp.actionArgs, &listReader{lists}, nil)
	if err != nil {
		return err
	}
	tp.selectors = selectors
	return nil
}

func (tp *genericTracepoint) EventConfig() (api.EventConfig, error) {

	if len(tp.args) > api.EventConfigMaxArgs {
		return api.EventConfig{}, fmt.Errorf("number of arguments (%d) larger than max (%d)", len(tp.args), api.EventConfigMaxArgs)
	}

	config := api.EventConfig{}
	config.PolicyID = uint32(tp.policyID)
	config.FuncId = uint32(tp.tableIdx)
	// iterate over output arguments
	for i := range tp.args {
		tpArg := &tp.args[i]
		config.ArgTpCtxOff[i] = uint32(tpArg.CtxOffset)
		_, err := tpArg.setGenericTypeId()
		if err != nil {
			return api.EventConfig{}, fmt.Errorf("output argument %v unsupported: %w", tpArg, err)
		}

		config.Arg[i] = int32(tpArg.genericTypeId)
		config.ArgM[i] = uint32(tpArg.MetaArg)

		tracepointLog.Debugf("configured argument #%d: %+v (type:%d)", i, tpArg, tpArg.genericTypeId)
	}

	// nop args
	for i := len(tp.args); i < api.EventConfigMaxArgs; i++ {
		config.ArgTpCtxOff[i] = uint32(0)
		config.Arg[i] = int32(gt.GenericNopType)
		config.ArgM[i] = uint32(0)
	}

	return config, nil
}

func LoadGenericTracepointSensor(bpfDir string, load *program.Program, verbose int) error {

	tracepointLog = logger.GetLogger()

	tpIdx, ok := load.LoaderData.(int)
	if !ok {
		return fmt.Errorf("loaderData for genericTracepoint %s is %T (%v) (not an int)", load.Name, load.LoaderData, load.LoaderData)
	}

	tp, err := genericTracepointTable.getTracepoint(tpIdx)
	if err != nil {
		return fmt.Errorf("Could not find generic tracepoint information for %s: %w", load.Attach, err)
	}

	load.MapLoad = append(load.MapLoad, selectorsMaploads(tp.selectors, 0)...)

	config, err := tp.EventConfig()
	if err != nil {
		return fmt.Errorf("failed to generate config data for generic tracepoint: %w", err)
	}
	var binBuf bytes.Buffer
	binary.Write(&binBuf, binary.LittleEndian, config)
	cfg := &program.MapLoad{
		Index: 0,
		Name:  "config_map",
		Load: func(m *ebpf.Map, _ string, index uint32) error {
			return m.Update(index, binBuf.Bytes()[:], ebpf.UpdateAny)
		},
	}
	load.MapLoad = append(load.MapLoad, cfg)

	if err := program.LoadTracepointProgram(bpfDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic tracepoint program: %s -> %s", load.Name, load.Attach)
	} else {
		return err
	}

	return err
}

func handleGenericTracepoint(r *bytes.Reader) ([]observer.Event, error) {
	m := tracingapi.MsgGenericTracepoint{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to read tracepoint: %w", err)
	}

	unix := &tracing.MsgGenericTracepointUnix{
		Msg:    &m,
		Subsys: "UNKNOWN",
		Event:  "UNKNOWN",
	}

	tp, err := genericTracepointTable.getTracepoint(int(m.FuncId))
	if err != nil {
		logger.GetLogger().WithField("id", m.FuncId).WithError(err).Warnf("genericTracepoint info not found")
		return []observer.Event{unix}, nil
	}

	ret, err := handleMsgGenericTracepoint(&m, unix, tp, r)
	if tp.customHandler != nil {
		ret, err = tp.customHandler(ret, err)
	}
	return ret, err
}

func handleMsgGenericTracepoint(
	m *tracingapi.MsgGenericTracepoint,
	unix *tracing.MsgGenericTracepointUnix,
	tp *genericTracepoint,
	r *bytes.Reader,
) ([]observer.Event, error) {

	switch m.ActionId {
	case selectors.ActionTypeGetUrl, selectors.ActionTypeDnsLookup:
		actionArgEntry, err := tp.actionArgs.GetEntry(idtable.EntryID{ID: int(m.ActionArgId)})
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Failed to find argument for id:%d", m.ActionArgId)
			return nil, fmt.Errorf("Failed to find argument for id")
		}
		actionArg := actionArgEntry.(*selectors.ActionArgEntry).GetArg()
		switch m.ActionId {
		case selectors.ActionTypeGetUrl:
			logger.GetLogger().WithField("URL", actionArg).Trace("Get URL Action")
			getUrl(actionArg)
		case selectors.ActionTypeDnsLookup:
			logger.GetLogger().WithField("FQDN", actionArg).Trace("DNS lookup")
			dnsLookup(actionArg)
		}
	}

	unix.Subsys = tp.Info.Subsys
	unix.Event = tp.Info.Event
	unix.PolicyName = tp.policyName
	unix.Message = tp.message
	unix.Tags = tp.tags

	for idx, out := range tp.args {

		if out.nopTy {
			continue
		}

		switch out.genericTypeId {
		case gt.GenericU64Type:
			var val uint64
			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case gt.GenericS64Type:
			var val int64
			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case gt.GenericU32Type:
			var val uint32
			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case gt.GenericIntType, gt.GenericS32Type:
			var val int32
			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case gt.GenericSizeType:
			var val uint64

			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case gt.GenericCharBuffer, gt.GenericCharIovec:
			if arg, err := ReadArgBytes(r, idx, false); err == nil {
				unix.Args = append(unix.Args, arg.Value)
			} else {
				logger.GetLogger().WithError(err).Warnf("failed to read bytes argument")
			}

		case gt.GenericConstBuffer:
			if out.format == nil {
				logger.GetLogger().Warn("GenericConstBuffer lacks format. Cannot decode argument")
				break
			}
			if arrTy, ok := out.format.Field.Type.(tracepoint.ArrayTy); ok {
				intTy, ok := arrTy.Ty.(tracepoint.IntTy)
				if !ok {
					logger.GetLogger().Warn("failed to read array argument: expecting array of integers")
					break
				}

				switch intTy.Base {
				case tracepoint.IntTyLong:
					var val uint64
					for i := 0; i < int(arrTy.Size); i++ {
						err := binary.Read(r, binary.LittleEndian, &val)
						if err != nil {
							logger.GetLogger().WithError(err).Warnf("failed to read element %d from array", i)
							return nil, err
						}
						unix.Args = append(unix.Args, val)
					}
				default:
					logger.GetLogger().Warnf("failed to read array argument: unexpected base type: %w", intTy.Base)
				}
			}
		case gt.GenericStringType, gt.GenericDataLoc:
			if arg, err := parseString(r); err != nil {
				logger.GetLogger().WithError(err).Warn("error parsing arg type string")
			} else {
				unix.Args = append(unix.Args, arg)
			}
		case gt.GenericSkbType:
			var skb api.MsgGenericKprobeSkb
			var arg api.MsgGenericKprobeArgSkb

			err := binary.Read(r, binary.LittleEndian, &skb)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("skb type err")
			}

			arg.Hash = skb.Hash
			arg.Len = skb.Len
			arg.Priority = skb.Priority
			arg.Mark = skb.Mark
			arg.Family = skb.Tuple.Family
			arg.Saddr = network.GetIP(skb.Tuple.Saddr, skb.Tuple.Family).String()
			arg.Daddr = network.GetIP(skb.Tuple.Daddr, skb.Tuple.Family).String()
			arg.Sport = uint32(skb.Tuple.Sport)
			arg.Dport = uint32(skb.Tuple.Dport)
			arg.Proto = uint32(skb.Tuple.Protocol)
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

			arg.Family = sock.Tuple.Family
			arg.State = sock.State
			arg.Type = sock.Type
			arg.Protocol = sock.Tuple.Protocol
			arg.Mark = sock.Mark
			arg.Priority = sock.Priority
			arg.Saddr = network.GetIP(sock.Tuple.Saddr, sock.Tuple.Family).String()
			arg.Daddr = network.GetIP(sock.Tuple.Daddr, sock.Tuple.Family).String()
			arg.Sport = uint32(sock.Tuple.Sport)
			arg.Dport = uint32(sock.Tuple.Dport)
			arg.Sockaddr = sock.Sockaddr
			unix.Args = append(unix.Args, arg)

		case gt.GenericSyscall64:
			var val uint64
			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			if option.Config.CompatibilitySyscall64SizeType {
				// NB: clear Is32Bit to mantain previous behaviour
				val = val & (^uint64(Is32Bit))
				unix.Args = append(unix.Args, val)
			} else {
				val := parseSyscall64Value(val)
				unix.Args = append(unix.Args, val)
			}

		default:
			logger.GetLogger().Warnf("handleGenericTracepoint: ignoring:  %+v", out)
		}
	}
	return []observer.Event{unix}, nil
}

func (t *observerTracepointSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return LoadGenericTracepointSensor(args.BPFDir, args.Load, args.Verbose)
}
