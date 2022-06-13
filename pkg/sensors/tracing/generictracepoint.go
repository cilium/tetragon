// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"reflect"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
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
	// maximum arguments that bpf-side supports
	genericTP_MaxArgs = 5
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
	sensors.RegisterTracingSensorsAtInit(tp.name, tp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_TRACEPOINT, handleGenericTracepoint)
}

// genericTracepoint is the internal representation of a tracepoint
type genericTracepoint struct {
	Info *tracepoint.Tracepoint
	args []genericTracepointArg

	Selectors *v1alpha1.TracepointSpec

	// index to access this on genericTracepointTable
	tableIdx int
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
	arr []*genericTracepoint
}

// addTracepoint adds a tracepoint to the table, and sets its .tableIdx field
// to be the index to retrieve it from the table.
func (t *tracepointTable) addTracepoint(tp *genericTracepoint) {
	idx := len(t.arr)
	t.arr = append(t.arr, tp)
	tp.tableIdx = idx
}

// getTracepoint retrieves a tracepoint from the table using its id
func (t *tracepointTable) getTracepoint(idx int) (*genericTracepoint, error) {
	if idx < len(t.arr) {
		return t.arr[idx], nil
	}
	return nil, fmt.Errorf("tracepoint table: invalid id:%d (len=%d)", idx, len(t.arr))
}

// GenericTracepointConf is the configuration for a generic tracepoint. This is
// a caller-defined structure that configures a tracepoint.
type GenericTracepointConf = v1alpha1.TracepointSpec

// GenericTracepointConfArg represents an argument of a generic tracepoint
//
// This points to the index of the argument.
// (Another option might be to specify this by name)
type GenericTracepointConfArg v1alpha1.KProbeArg

// getTracepointMetaArg is a temporary helper to find meta values while tracepoint
// converts into new CRD and config formats.
func getTracepointMetaValue(arg *GenericTracepointConfArg) int {
	if arg.SizeArgIndex > 0 {
		return int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		return -1
	}
	return 0
}

// NB: making this a method of GenericTracepointConfArg means that we can have
// this as an interface (e.g,. for implementing output by name)
func (conf *GenericTracepointConfArg) configureTracepointArg(tp *genericTracepoint) error {
	if conf.Index >= uint32(len(tp.Info.Format.Fields)) {
		return fmt.Errorf("tracepoint %s/%s has %d fields but field %d was requested",
			tp.Info.Subsys, tp.Info.Event, len(tp.Info.Format.Fields), conf.Index)
	}
	field := tp.Info.Format.Fields[conf.Index]

	metaTp := getTracepointMetaValue(conf)

	argIdx := uint32(len(tp.args))
	tp.args = append(tp.args, genericTracepointArg{
		CtxOffset:     int(field.Offset),
		ArgIdx:        argIdx,
		TpIdx:         int(conf.Index),
		MetaTp:        metaTp,
		nopTy:         false,
		format:        &field,
		genericTypeId: gt.GenericInvalidType,
	})
	return nil
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

// createGenericTracepoint creates the genericTracepoint information based on
// the user-provided configuration
func createGenericTracepoint(conf *GenericTracepointConf) (*genericTracepoint, error) {
	tp := tracepoint.Tracepoint{
		Subsys: conf.Subsystem,
		Event:  conf.Event,
	}

	if err := tp.LoadFormat(); err != nil {
		return nil, fmt.Errorf("tracepoint %s/%s not supported: %w", tp.Subsys, tp.Event, err)
	}

	ret := &genericTracepoint{
		Info:      &tp,
		Selectors: conf,
	}

	for i := range conf.Args {
		arg := GenericTracepointConfArg{
			Index:        conf.Args[i].Index,
			SizeArgIndex: conf.Args[i].SizeArgIndex,
			ReturnCopy:   conf.Args[i].ReturnCopy,
		}
		if err := arg.configureTracepointArg(ret); err != nil {
			return nil, err
		}
	}

	getOrAppend := func(metaTp int) (*genericTracepointArg, error) {
		tpIdx := metaTp - 1
		for i := range ret.args {
			if ret.args[i].TpIdx == tpIdx {
				return &ret.args[i], nil
			}
		}

		if tpIdx >= len(ret.Info.Format.Fields) {
			return nil, fmt.Errorf(
				"tracepoint %s/%s has %d fields but field %d was requested in a metadata argument",
				ret.Info.Subsys, ret.Info.Event, len(ret.Info.Format.Fields), tpIdx)
		}
		field := ret.Info.Format.Fields[tpIdx]
		argIdx := uint32(len(ret.args))
		ret.args = append(ret.args, genericTracepointArg{
			CtxOffset:     int(field.Offset),
			ArgIdx:        argIdx,
			TpIdx:         tpIdx,
			MetaTp:        0,
			MetaArg:       0,
			nopTy:         true,
			format:        &field,
			genericTypeId: gt.GenericInvalidType,
		})
		return &ret.args[argIdx], nil
	}

	for idx := 0; idx < len(ret.args); idx++ {
		meta := ret.args[idx].MetaTp
		if meta == 0 || meta == -1 {
			ret.args[idx].MetaArg = meta
			continue
		}
		a, err := getOrAppend(meta)
		if err != nil {
			return nil, err
		}
		ret.args[idx].MetaArg = int(a.ArgIdx) + 1
	}

	genericTracepointTable.addTracepoint(ret)
	return ret, nil
}

// createGenericTracepointSensor will create a sensor that can be loaded based on a generic tracepoint configuration
func createGenericTracepointSensor(confs []GenericTracepointConf) (*sensors.Sensor, error) {

	tracepoints := make([]*genericTracepoint, 0, len(confs))
	for _, conf := range confs {
		tp, err := createGenericTracepoint(&conf)
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
		attach := fmt.Sprintf("%s/%s", tp.Info.Subsys, tp.Info.Event)
		prog0 := program.Builder(
			path.Join(option.Config.HubbleLib, progName),
			attach,
			"tracepoint/generic_tracepoint",
			fmt.Sprintf("tracepoint-%s-%s", tp.Info.Subsys, tp.Info.Event),
			"generic_tracepoint",
		)

		prog0.LoaderData = tp.tableIdx
		progs = append(progs, prog0)
	}

	return &sensors.Sensor{
		Name:  "generic_tracepoint_sensor",
		Progs: progs,
		Maps:  maps,
	}, nil
}

func LoadGenericTracepointSensor(bpfDir, mapDir string, load *program.Program, version, verbose int) (int, error) {
	config := &api.EventConfig{}

	tracepointLog = logger.GetLogger()

	tpIdx, ok := load.LoaderData.(int)
	if !ok {
		return 0, fmt.Errorf("loaderData for genericTracepoint %s is %T (%v) (not an int)", load.Name, load.LoaderData, load.LoaderData)
	}

	tp, err := genericTracepointTable.getTracepoint(tpIdx)
	if err != nil {
		return 0, fmt.Errorf("Could not find generic tracepoint information for %s: %w", load.Attach, err)
	}

	btfObj, err := btf.NewBTF()
	if err != nil {
		return 0, err
	}
	defer btfObj.Close()

	config.FuncId = uint32(tp.tableIdx)

	// iterate over output arguments
	for i := range tp.args {
		tpArg := &tp.args[i]

		config.ArgTpCtxOff[i] = uint32(tpArg.CtxOffset)
		_, err := tpArg.setGenericTypeId()
		if err != nil {
			return 0, fmt.Errorf("output argument %v unsupported: %w", tpArg, err)
		}

		config.Arg[i] = int32(tpArg.genericTypeId)
		config.ArgM[i] = uint32(tpArg.MetaArg)

		tracepointLog.Debugf("configured argument #%d: %+v (type:%d)", i, tpArg, tpArg.genericTypeId)
	}

	// nop args
	for i := len(tp.args); i < genericTP_MaxArgs; i++ {
		config.ArgTpCtxOff[i] = uint32(0)
		config.Arg[i] = int32(gt.GenericNopType)
		config.ArgM[i] = uint32(0)
	}

	// rewrite arg index
	for i := range tp.args {
		tpArg := &tp.args[i]

		ty, err := tpArg.setGenericTypeId()
		if err != nil {
			return 0, fmt.Errorf("output argument %v unsupported: %w", tpArg, err)
		}

		if len(tp.Selectors.Args) > i && tp.Selectors.Args[i].Type == "" {
			tp.Selectors.Args[i].Type = selectors.ArgTypeToString(uint32(ty))
		}

		for j, arg := range tp.Selectors.Args {
			if arg.Index == uint32(tpArg.TpIdx) {
				tp.Selectors.Args[j].Index = tpArg.ArgIdx
			}
		}
		for j, s := range tp.Selectors.Selectors {
			for k, match := range s.MatchArgs {
				if match.Index == uint32(tpArg.TpIdx) {
					tp.Selectors.Selectors[j].MatchArgs[k].Index = uint32(tpArg.ArgIdx)
				}
			}
		}
	}

	kernelSelectors, err := selectors.InitTracepointSelectors(tp.Selectors)
	if err != nil {
		return 0, err
	}

	return bpf.LoadTracepointArgsProgram(
		version, option.Config.Verbosity,
		uintptr(btfObj),
		load.Name,
		load.Attach,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		load.RetProbe,
		kernelSelectors,
		config,
	)
}

func handleGenericTracepoint(r *bytes.Reader) ([]observer.Event, error) {
	m := tracingapi.MsgGenericTracepoint{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to read tracepoint: %w", err)
	}

	unix := &tracingapi.MsgGenericTracepointUnix{
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

	if len(spec.KProbes) > 0 && len(spec.Tracepoints) > 0 {
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	}
	if len(spec.Tracepoints) > 0 {
		return createGenericTracepointSensor(spec.Tracepoints)
	}
	return nil, nil
}

func (t *observerTracepointSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return LoadGenericTracepointSensor(args.BPFDir, args.MapDir, args.Load, args.Version, args.Verbose)
}
