// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
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

	sensorCounter uint64
)

type observerTracepointSensor struct {
	name string
}

func init() {
	tp := &observerTracepointSensor{
		name: "tracepoint sensor",
	}
	sensors.RegisterProbeType("generic_tracepoint", tp)
	sensors.RegisterTracingSensorsAtInit(tp.name, tp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_TRACEPOINT, handleGenericTracepoint)
}

// genericTracepoint is the internal representation of a tracepoint
type genericTracepoint struct {
	Info *tracepoint.Tracepoint
	args []genericTracepointArg

	Spec *v1alpha1.TracepointSpec

	// index to access this on genericTracepointTable
	tableIdx int

	pinPathPrefix string
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

// GenericTracepointConf is the configuration for a generic tracepoint. This is
// a caller-defined structure that configures a tracepoint.
type GenericTracepointConf = v1alpha1.TracepointSpec

// getTracepointMetaArg is a temporary helper to find meta values while tracepoint
// converts into new CRD and config formats.
func getTracepointMetaValue(arg *v1alpha1.KProbeArg) int {
	if arg.SizeArgIndex > 0 {
		return int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		return -1
	}
	return 0
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
func createGenericTracepoint(sensorName string, conf *GenericTracepointConf) (*genericTracepoint, error) {
	tp := tracepoint.Tracepoint{
		Subsys: conf.Subsystem,
		Event:  conf.Event,
	}

	if err := tp.LoadFormat(); err != nil {
		return nil, fmt.Errorf("tracepoint %s/%s not supported: %w", tp.Subsys, tp.Event, err)
	}

	tpArgs, err := buildGenericTracepointArgs(&tp, conf.Args)
	if err != nil {
		return nil, err
	}

	ret := &genericTracepoint{
		Info: &tp,
		Spec: conf,
		args: tpArgs,
	}

	genericTracepointTable.addTracepoint(ret)
	ret.pinPathPrefix = sensors.PathJoin(sensorName, fmt.Sprintf("gtp-%d", ret.tableIdx))
	return ret, nil
}

// createGenericTracepointSensor will create a sensor that can be loaded based on a generic tracepoint configuration
func createGenericTracepointSensor(name string, confs []GenericTracepointConf) (*sensors.Sensor, error) {

	tracepoints := make([]*genericTracepoint, 0, len(confs))
	for i := range confs {
		tp, err := createGenericTracepoint(name, &confs[i])
		if err != nil {
			return nil, err
		}
		tracepoints = append(tracepoints, tp)
	}

	progName := "bpf_generic_tracepoint.o"
	if kernels.EnableLargeProgs() {
		progName = "bpf_generic_tracepoint_v53.o"
	}

	maps := []*program.Map{}
	progs := make([]*program.Program, 0, len(tracepoints))
	for _, tp := range tracepoints {
		pinPath := tp.pinPathPrefix
		pinProg := sensors.PathJoin(pinPath, fmt.Sprintf("%s:%s_prog", tp.Info.Subsys, tp.Info.Event))
		attach := fmt.Sprintf("%s/%s", tp.Info.Subsys, tp.Info.Event)
		prog0 := program.Builder(
			path.Join(option.Config.HubbleLib, progName),
			attach,
			"tracepoint/generic_tracepoint",
			pinProg,
			"generic_tracepoint",
		)

		prog0.LoaderData = tp.tableIdx
		progs = append(progs, prog0)

		fdinstall := program.MapBuilderPin("fdinstall_map", sensors.PathJoin(pinPath, "fdinstall_map"), prog0)
		maps = append(maps, fdinstall)

		tailCalls := program.MapBuilderPin("tp_calls", sensors.PathJoin(pinPath, "tp_calls"), prog0)
		maps = append(maps, tailCalls)

		filterMap := program.MapBuilderPin("filter_map", sensors.PathJoin(pinPath, "filter_map"), prog0)
		maps = append(maps, filterMap)

		argFilterMaps := program.MapBuilderPin("argfilter_maps", sensors.PathJoin(pinPath, "argfilter_maps"), prog0)
		maps = append(maps, argFilterMaps)
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
	}, nil
}

func (tp *genericTracepoint) KernelSelectors() (*selectors.KernelSelectorState, error) {
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
			return nil, fmt.Errorf("output argument %v unsupported: %w", tpArg, err)
		}
		selType := selectors.ArgTypeToString(uint32(ty))

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

	return selectors.InitKernelSelectorState(selSelectors, selArgs)
}

func (tp *genericTracepoint) EventConfig() (api.EventConfig, error) {

	if len(tp.args) > api.EventConfigMaxArgs {
		return api.EventConfig{}, fmt.Errorf("number of arguments (%d) larger than max (%d)", len(tp.args), api.EventConfigMaxArgs)
	}

	config := api.EventConfig{}
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

	if selectors.MatchActionSigKill(tp.Spec) {
		config.Sigkill = 1
	}

	return config, nil
}

// ReloadGenericTracepointSelectors will reload a tracepoint by unlinking it, generating new
// selector data and updating filter_map, and then relinking the tracepoint.
//
// This is intended for speeding up testing, so DO NOT USE elsewhere without checking its
// implementation first because limitations may exist (e.g., the config map is not updated).
// TODO: pass the sensor here
func ReloadGenericTracepointSelectors(p *program.Program, conf *v1alpha1.TracepointSpec) error {
	tpIdx, ok := p.LoaderData.(int)
	if !ok {
		return fmt.Errorf("loaderData for genericTracepoint %s is %T (%v) (not an int)", p.Name, p.LoaderData, p.LoaderData)
	}

	tp, err := genericTracepointTable.getTracepoint(tpIdx)
	if err != nil {
		return fmt.Errorf("Could not find generic tracepoint information for %s: %w", p.Attach, err)
	}

	if err := p.Unlink(); err != nil {
		return fmt.Errorf("unlinking %v failed: %s", p, err)
	}

	tp.Info.Subsys = conf.Subsystem
	tp.Info.Event = conf.Event
	if err := tp.Info.LoadFormat(); err != nil {
		return fmt.Errorf("tracepoint %s/%s not supported: %w", conf.Subsystem, conf.Event, err)
	}

	tp.Spec = conf
	tp.args, err = buildGenericTracepointArgs(tp.Info, conf.Args)
	if err != nil {
		return err
	}

	kernelSelectors, err := tp.KernelSelectors()
	if err != nil {
		return err
	}

	if err := updateSelectors(kernelSelectors, p.PinMap, tp.pinPathPrefix); err != nil {
		return err
	}

	if err := p.Relink(); err != nil {
		return fmt.Errorf("failed relinking %v: %w", p, err)
	}

	return nil
}

func LoadGenericTracepointSensor(bpfDir, mapDir string, load *program.Program, version, verbose int) error {

	tracepointLog = logger.GetLogger()

	tpIdx, ok := load.LoaderData.(int)
	if !ok {
		return fmt.Errorf("loaderData for genericTracepoint %s is %T (%v) (not an int)", load.Name, load.LoaderData, load.LoaderData)
	}

	tp, err := genericTracepointTable.getTracepoint(tpIdx)
	if err != nil {
		return fmt.Errorf("Could not find generic tracepoint information for %s: %w", load.Attach, err)
	}

	kernelSelectors, err := tp.KernelSelectors()
	if err != nil {
		return err
	}
	load.MapLoad = append(load.MapLoad, selectorsMaploads(kernelSelectors, tp.pinPathPrefix, 0)...)

	config, err := tp.EventConfig()
	if err != nil {
		return fmt.Errorf("failed to generate config data for generic tracepoint: %w", err)
	}
	var binBuf bytes.Buffer
	binary.Write(&binBuf, binary.LittleEndian, config)
	cfg := &program.MapLoad{
		Index: 0,
		Name:  "config_map",
		Load: func(m *ebpf.Map, index uint32) error {
			return m.Update(index, binBuf.Bytes()[:], ebpf.UpdateAny)
		},
	}
	load.MapLoad = append(load.MapLoad, cfg)

	return program.LoadTracepointProgram(bpfDir, mapDir, load, verbose)
}

func handleGenericTracepoint(r *bytes.Reader) ([]observer.Event, error) {
	m := tracingapi.MsgGenericTracepoint{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to read tracepoint: %w", err)
	}

	unix := &tracing.MsgGenericTracepointUnix{
		Common:     m.Common,
		ProcessKey: m.ProcessKey,
		Id:         m.Id,
		Subsys:     "UNKNOWN",
		Event:      "UNKNOWN",
	}

	tp, err := genericTracepointTable.getTracepoint(int(m.Id))
	if err != nil {
		logger.GetLogger().WithField("id", m.Id).WithError(err).Warnf("genericTracepoint info not found")
		return []observer.Event{unix}, nil
	}

	unix.Subsys = tp.Info.Subsys
	unix.Event = tp.Info.Event

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

		case gt.GenericSizeType:
			var val uint64

			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case gt.GenericCharBuffer, gt.GenericCharIovec:
			if arg, err := ReadArgBytes(r, idx); err == nil {
				unix.Args = append(unix.Args, arg.Value)
			} else {
				logger.GetLogger().WithError(err).Warnf("failed to read bytes argument")
			}

		case gt.GenericConstBuffer:
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

		default:
			logger.GetLogger().Warnf("handleGenericTracepoint: ignoring:  %+v", out)
		}
	}
	return []observer.Event{unix}, nil
}

func (t *observerTracepointSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec, ok := raw.(*v1alpha1.TracingPolicySpec)
	if !ok {
		s, ok := reflect.Indirect(reflect.ValueOf(raw)).FieldByName("TracingPolicySpec").Interface().(v1alpha1.TracingPolicySpec)
		if !ok {
			return nil, nil
		}
		spec = &s
	}
	name := fmt.Sprintf("gtp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))

	if len(spec.KProbes) > 0 && len(spec.Tracepoints) > 0 {
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	}
	if len(spec.Tracepoints) > 0 {
		return createGenericTracepointSensor(name, spec.Tracepoints)
	}
	return nil, nil
}

func (t *observerTracepointSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return LoadGenericTracepointSensor(args.BPFDir, args.MapDir, args.Load, args.Version, args.Verbose)
}
