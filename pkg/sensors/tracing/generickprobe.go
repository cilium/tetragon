// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	cachedbtf "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/network"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"

	gt "github.com/cilium/tetragon/pkg/generictypes"
)

type observerKprobeSensor struct {
	name string
}

func init() {
	kprobe := &observerKprobeSensor{
		name: "kprobe sensor",
	}
	sensors.RegisterProbeType("generic_kprobe", kprobe)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_KPROBE, handleGenericKprobe)
}

const (
	CharBufErrorENOMEM      = -1
	CharBufErrorPageFault   = -2
	CharBufErrorTooLarge    = -3
	CharBufSavedForRetprobe = -4
)

func kprobeCharBufErrorToString(e int32) string {
	switch e {
	case CharBufErrorENOMEM:
		return "CharBufErrorENOMEM"
	case CharBufErrorTooLarge:
		return "CharBufErrorBufTooLarge"
	case CharBufErrorPageFault:
		return "CharBufErrorPageFault"
	}
	return "CharBufErrorUnknown"
}

type kprobeLoadArgs struct {
	selectors *selectors.KernelSelectorState
	retprobe  bool
	syscall   bool
	config    *api.EventConfig
}

type argPrinters struct {
	ty      int
	index   int
	maxData bool
	label   string
}

type pendingEventKey struct {
	eventId    uint64
	ktimeEnter uint64
}

// internal genericKprobe info
type genericKprobe struct {
	loadArgs          kprobeLoadArgs
	argSigPrinters    []argPrinters
	argReturnPrinters []argPrinters
	funcName          string

	// userReturnFilters are filter specs implemented in userspace after
	// receiving events on the return value. We currently use this for return
	// arg filtering.
	userReturnFilters []v1alpha1.ArgSelector

	// for kprobes that have a retprobe, we maintain the enter events in
	// the map, so that we can merge them when the return event is
	// generated. The events are maintained in the map below, using
	// the retprobe_id (thread_id) and the enter ktime as the key.
	pendingEvents *lru.Cache[pendingEventKey, pendingEvent]

	tableId idtable.EntryID

	// for kprobes that have a GetUrl or DnsLookup action, we store the table of arguments.
	actionArgs idtable.Table

	pinPathPrefix string

	// policyName is the name of the policy that this tracepoint belongs to
	policyName string

	// is there override defined for the kprobe
	hasOverride bool

	// reference to a stack trace map, must be closed when unloading the kprobe,
	// this is done in the sensor PostUnloadHook
	stackTraceMapRef *ebpf.Map

	customHandler eventhandler.Handler
}

// pendingEvent is an event waiting to be merged with another event.
// This is needed for retprobe probes that generate two events: one at the
// function entry, and one at the function return. We merge these events into
// one, before returning it to the user.
type pendingEvent struct {
	ev          *tracing.MsgGenericKprobeUnix
	returnEvent bool
}

func (g *genericKprobe) SetID(id idtable.EntryID) {
	g.tableId = id
}

var (
	// genericKprobeTable is a global table that maintains information for generic kprobes
	genericKprobeTable idtable.Table
)

func genericKprobeTableGet(id idtable.EntryID) (*genericKprobe, error) {
	entry, err := genericKprobeTable.GetEntry(id)
	if err != nil {
		return nil, fmt.Errorf("getting entry from genericKprobeTable failed with: %w", err)
	}
	val, ok := entry.(*genericKprobe)
	if !ok {
		return nil, fmt.Errorf("getting entry from genericKprobeTable failed with: got invalid type: %T (%v)", entry, entry)
	}
	return val, nil
}

var (
	MaxFilterIntArgs = 8
)

const (
	argReturnCopyBit = 1 << 4
	argMaxDataBit    = 1 << 5
)

func argReturnCopy(meta int) bool {
	return meta&argReturnCopyBit != 0
}

// meta value format:
// bits
//
//	0-3 : SizeArgIndex
//	  4 : ReturnCopy
//	  5 : MaxData
func getMetaValue(arg *v1alpha1.KProbeArg) (int, error) {
	var meta int

	if arg.SizeArgIndex > 0 {
		if arg.SizeArgIndex > 15 {
			return 0, fmt.Errorf("invalid SizeArgIndex value (>15): %v", arg.SizeArgIndex)
		}
		meta = int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		meta = meta | argReturnCopyBit
	}
	if arg.MaxData {
		meta = meta | argMaxDataBit
	}
	return meta, nil
}

func multiKprobePinPath(sensorPath string) string {
	return sensors.PathJoin(sensorPath, "multi_kprobe")
}

func createMultiKprobeSensor(sensorPath string, multiIDs, multiRetIDs []idtable.EntryID) ([]*program.Program, []*program.Map) {
	var progs []*program.Program
	var maps []*program.Map

	loadProgName := "bpf_multi_kprobe_v53.o"
	loadProgRetName := "bpf_multi_retkprobe_v53.o"
	if kernels.EnableV61Progs() {
		loadProgName = "bpf_multi_kprobe_v61.o"
		loadProgRetName = "bpf_multi_retkprobe_v61.o"
	}

	pinPath := multiKprobePinPath(sensorPath)

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("%d functions", len(multiIDs)),
		"kprobe.multi/generic_kprobe",
		pinPath,
		"generic_kprobe").
		SetLoaderData(multiIDs)
	progs = append(progs, load)

	fdinstall := program.MapBuilderPin("fdinstall_map", sensors.PathJoin(sensorPath, "fdinstall_map"), load)
	maps = append(maps, fdinstall)

	configMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "config_map"), load)
	maps = append(maps, configMap)

	tailCalls := program.MapBuilderPin("kprobe_calls", sensors.PathJoin(pinPath, "kp_calls"), load)
	maps = append(maps, tailCalls)

	filterMap := program.MapBuilderPin("filter_map", sensors.PathJoin(pinPath, "filter_map"), load)
	maps = append(maps, filterMap)

	argFilterMaps := program.MapBuilderPin("argfilter_maps", sensors.PathJoin(pinPath, "argfilter_maps"), load)
	// NB: code depends on multi kprobe links which was merged in 5.17, so the expectation is
	// that we do not need to SetInnerMaxEntries() here.
	maps = append(maps, argFilterMaps)

	addr4FilterMaps := program.MapBuilderPin("addr4lpm_maps", sensors.PathJoin(pinPath, "addr4lpm_maps"), load)
	// NB: code depends on multi kprobe links which was merged in 5.17, so the expectation is
	// that we do not need to SetInnerMaxEntries() here.
	maps = append(maps, addr4FilterMaps)

	addr6FilterMaps := program.MapBuilderPin("addr6lpm_maps", sensors.PathJoin(pinPath, "addr6lpm_maps"), load)
	// NB: code depends on multi kprobe links which was merged in 5.17, so the expectation is
	// that we do not need to SetInnerMaxEntries() here.
	maps = append(maps, addr6FilterMaps)

	fileIdentifierMaps := program.MapBuilderPin("fileid_maps", sensors.PathJoin(pinPath, "fileid_maps"), load)
	// NB: code depends on multi kprobe links which was merged in 5.17, so the expectation is
	// that we do not need to SetInnerMaxEntries() here.
	maps = append(maps, fileIdentifierMaps)

	var stringFilterMap [selectors.StringMapsNumSubMaps]*program.Map
	for string_map_index := 0; string_map_index < selectors.StringMapsNumSubMaps; string_map_index++ {
		stringFilterMap[string_map_index] = program.MapBuilderPin(fmt.Sprintf("string_maps_%d", string_map_index),
			sensors.PathJoin(pinPath, fmt.Sprintf("string_maps_%d", string_map_index)), load)
		// NB: code depends on multi kprobe links which was merged in 5.17, so the expectation is
		// that we do not need to SetInnerMaxEntries() here.
		maps = append(maps, stringFilterMap[string_map_index])
	}

	stringPrefixFilterMaps := program.MapBuilderPin("string_prefix_maps", sensors.PathJoin(pinPath, "string_prefix_maps"), load)
	// NB: code depends on multi kprobe links which was merged in 5.17, so the expectation is
	// that we do not need to SetInnerMaxEntries() here.
	maps = append(maps, stringPrefixFilterMaps)

	stringPostfixFilterMaps := program.MapBuilderPin("string_postfix_maps", sensors.PathJoin(pinPath, "string_postfix_maps"), load)
	// NB: code depends on multi kprobe links which was merged in 5.17, so the expectation is
	// that we do not need to SetInnerMaxEntries() here.
	maps = append(maps, stringPostfixFilterMaps)

	retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), load)
	maps = append(maps, retProbe)

	callHeap := program.MapBuilderPin("process_call_heap", sensors.PathJoin(pinPath, "process_call_heap"), load)
	maps = append(maps, callHeap)

	selNamesMap := program.MapBuilderPin("sel_names_map", sensors.PathJoin(pinPath, "sel_names_map"), load)
	maps = append(maps, selNamesMap)

	stackTraceMap := program.MapBuilderPin("stack_trace_map", sensors.PathJoin(pinPath, "stack_trace_map"), load)
	maps = append(maps, stackTraceMap)

	if kernels.EnableLargeProgs() {
		socktrack := program.MapBuilderPin("socktrack_map", sensors.PathJoin(sensorPath, "socktrack_map"), load)
		maps = append(maps, socktrack)
	}

	filterMap.SetMaxEntries(len(multiIDs))
	configMap.SetMaxEntries(len(multiIDs))

	if len(multiRetIDs) != 0 {
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			fmt.Sprintf("%d retkprobes", len(multiIDs)),
			"kprobe.multi/generic_retkprobe",
			"multi_retkprobe",
			"generic_kprobe").
			SetRetProbe(true).
			SetLoaderData(multiRetIDs)
		progs = append(progs, loadret)

		retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), loadret)
		maps = append(maps, retProbe)

		retConfigMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "retprobe_config_map"), loadret)
		maps = append(maps, retConfigMap)

		callHeap := program.MapBuilderPin("process_call_heap", sensors.PathJoin(pinPath, "process_call_heap"), loadret)
		maps = append(maps, callHeap)

		fdinstall := program.MapBuilderPin("fdinstall_map", sensors.PathJoin(sensorPath, "fdinstall_map"), loadret)
		maps = append(maps, fdinstall)

		socktrack := program.MapBuilderPin("socktrack_map", sensors.PathJoin(sensorPath, "socktrack_map"), loadret)
		maps = append(maps, socktrack)

		retConfigMap.SetMaxEntries(len(multiRetIDs))
	}

	return progs, maps
}

// preValidateKprobes pre-validates the semantics and BTF information of a Kprobe spec
//
// Pre validate the kprobe semantics and BTF information in order to separate
// the kprobe errors from BPF related ones.
func preValidateKprobes(name string, kprobes []v1alpha1.KProbeSpec, lists []v1alpha1.ListSpec) error {
	btfobj, err := btf.NewBTF()
	if err != nil {
		return err
	}

	if len(option.Config.KMods) > 0 {
		btfobj, err = cachedbtf.AddModulesToSpec(btfobj, option.Config.KMods)
		if err != nil {
			return fmt.Errorf("adding modules to spec failed: %w", err)
		}
	}

	// validate lists first
	err = preValidateLists(lists)
	if err != nil {
		return err
	}

	for i := range kprobes {
		f := &kprobes[i]

		var list *v1alpha1.ListSpec

		// the f.Call is either defined as list:NAME
		// or specifies directly the function
		if strings.HasPrefix(f.Call, "list:") {
			listName := f.Call[len("list:"):]

			list = getList(listName, lists)
			if list == nil {
				return fmt.Errorf("Error list '%s' not found", listName)
			}
		} else if f.Syscall {
			// modifying f.Call directly since BTF validation
			// later will use v1alpha1.KProbeSpec object
			prefixedName, err := arch.AddSyscallPrefix(f.Call)
			if err != nil {
				logger.GetLogger().WithFields(logrus.Fields{
					"sensor": name,
				}).WithError(err).Warn("Kprobe spec pre-validation of syscall prefix failed")
			} else {
				f.Call = prefixedName
			}
		}

		for sid, selector := range f.Selectors {
			for mid, matchAction := range selector.MatchActions {
				if matchAction.StackTrace && matchAction.Action != "Post" {
					return fmt.Errorf("stackTrace can only be used along Post action: got stackTrace enabled in kprobes[%d].selectors[%d].matchActions[%d] with action '%s'", i, sid, mid, matchAction.Action)
				}
			}
		}

		// get the call possible values, either from f.Call or the list
		calls := func() []string {
			if list != nil {
				return list.Values
			}
			return []string{f.Call}
		}()

		if selectors.HasOverride(f) {
			if !bpf.HasOverrideHelper() {
				return fmt.Errorf("Error override action not supported, bpf_override_return helper not available")
			}
			if !f.Syscall {
				for idx := range calls {
					if strings.HasPrefix(calls[idx], "security_") == false {
						return fmt.Errorf("Error override action can be used only with syscalls and security_ hooks")
					}
				}
			}
		}

		if selectors.HasSigkillAction(f) && !kernels.EnableLargeProgs() {
			return fmt.Errorf("sigkill action requires kernel >= 5.3.0")
		}

		for idx := range calls {
			// Now go over BTF validation
			if err := btf.ValidateKprobeSpec(btfobj, calls[idx], f); err != nil {
				if warn, ok := err.(*btf.ValidationWarn); ok {
					logger.GetLogger().WithFields(logrus.Fields{
						"sensor": name,
					}).WithError(warn).Warn("Kprobe spec pre-validation failed, but will continue with loading")
				} else if e, ok := err.(*btf.ValidationFailed); ok {
					return fmt.Errorf("kprobe spec pre-validation failed: %w", e)
				} else {
					err = fmt.Errorf("invalid or old kprobe spec: %s", err)
					logger.GetLogger().WithFields(logrus.Fields{
						"sensor": name,
					}).WithError(err).Warn("Kprobe spec pre-validation failed, but will continue with loading")
				}
			} else {
				logger.GetLogger().WithFields(logrus.Fields{
					"sensor": name,
				}).Debug("Kprobe spec pre-validation succeeded")
			}
		}

		for idxArg, arg := range f.Args {
			if arg.Type == "auto" {
				return fmt.Errorf("spec.kprobes[%d].args[%d].type default 'auto' is invalid for a kprobe", i, idxArg)
			}
		}
	}

	return nil
}

const (
	flagsEarlyFilter = 1 << 0
)

func flagsString(flags uint32) string {
	s := "none"

	if flags&flagsEarlyFilter != 0 {
		s = "early_filter"
	}
	return s
}

func isGTOperator(op string) bool {
	return op == "GT" || op == "GreaterThan"
}

func isLTOperator(op string) bool {
	return op == "LT" || op == "LessThan"
}

type addKprobeIn struct {
	useMulti      bool
	sensorPath    string
	policyName    string
	policyID      policyfilter.PolicyID
	customHandler eventhandler.Handler
}

type addKprobeOut struct {
	multiIDs    []idtable.EntryID
	multiRetIDs []idtable.EntryID
	progs       []*program.Program
	maps        []*program.Map
	// identifier returned when the kprobe was added to the genericKprobeTable
	tableEntryIndex int
}

func getKprobeSymbols(symbol string, syscall bool, lists []v1alpha1.ListSpec) ([]string, bool, error) {
	if strings.HasPrefix(symbol, "list:") {
		name := symbol[len("list:"):]
		for idx := range lists {
			list := lists[idx]
			if list.Name == name {
				return list.Values, isSyscallListType(list.Type), nil
			}
		}
		return []string{""}, false, fmt.Errorf("list '%s' not found", name)
	}
	return []string{symbol}, syscall, nil
}

func createGenericKprobeSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	policyID policyfilter.PolicyID,
	policyName string,
	customHandler eventhandler.Handler,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var multiIDs, multiRetIDs []idtable.EntryID
	var useMulti bool
	var selMaps *selectors.KernelSelectorMaps

	kprobes := spec.KProbes
	lists := spec.Lists

	options, err := getKprobeOptions(spec.Options)
	if err != nil {
		return nil, fmt.Errorf("failed to set options: %s", err)
	}

	// use multi kprobe only if:
	// - it's not disabled by spec option
	// - it's not disabled by command line option
	// - there's support detected
	if !options.DisableKprobeMulti {
		useMulti = !option.Config.DisableKprobeMulti &&
			bpf.HasKprobeMulti()
	}

	in := addKprobeIn{
		useMulti:      useMulti,
		sensorPath:    name,
		policyID:      policyID,
		policyName:    policyName,
		customHandler: customHandler,
	}

	addedKprobeIndices := []int{}
	if useMulti {
		selMaps = &selectors.KernelSelectorMaps{}
	}
	for i := range kprobes {
		syms, syscall, err := getKprobeSymbols(kprobes[i].Call, kprobes[i].Syscall, lists)
		if err != nil {
			return nil, err
		}

		// Syscall flag might be changed in list definition
		kprobes[i].Syscall = syscall

		for idx := range syms {
			out, err := addKprobe(syms[idx], &kprobes[i], &in, selMaps)
			if err != nil {
				return nil, err
			}
			addedKprobeIndices = append(addedKprobeIndices, out.tableEntryIndex)

			if useMulti {
				multiRetIDs = append(multiRetIDs, out.multiRetIDs...)
				multiIDs = append(multiIDs, out.multiIDs...)
			} else {
				progs = append(progs, out.progs...)
				maps = append(maps, out.maps...)
			}
		}
	}

	if useMulti {
		progs, maps = createMultiKprobeSensor(in.sensorPath, multiIDs, multiRetIDs)
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
		PostUnloadHook: func() error {
			var errs error
			for _, idx := range addedKprobeIndices {
				entry, err := genericKprobeTable.GetEntry(idtable.EntryID{ID: idx})
				if err != nil {
					errs = errors.Join(errs, err)
				}

				// close the eventual reference to the stack trace map
				gk, ok := entry.(*genericKprobe)
				if !ok {
					errs = errors.Join(errs, fmt.Errorf("entry from genericKprobeTable with invalid type: %T (%v)", entry, entry))
				} else {
					if gk.stackTraceMapRef != nil {
						err = gk.stackTraceMapRef.Close()
						if err != nil {
							errs = errors.Join(errs, fmt.Errorf("failed to close map: %v", gk.stackTraceMapRef))
						}
						gk.stackTraceMapRef = nil
					}
				}
			}
			return errs
		},
		DestroyHook: func() error {
			var errs error
			for _, idx := range addedKprobeIndices {
				_, err := genericKprobeTable.RemoveEntry(idtable.EntryID{ID: idx})
				if err != nil {
					errs = errors.Join(errs, err)
				}
			}
			return errs
		},
	}, nil
}

// addKprobe will, amongst other things, create a generic kprobe entry and add
// it to the genericKprobeTable. The caller should make sure that this entry is
// properly removed on kprobe removal.
func addKprobe(funcName string, f *v1alpha1.KProbeSpec, in *addKprobeIn, selMaps *selectors.KernelSelectorMaps) (out *addKprobeOut, err error) {
	var argSigPrinters []argPrinters
	var argReturnPrinters []argPrinters
	var setRetprobe bool
	var argRetprobe *v1alpha1.KProbeArg
	var argsBTFSet [api.MaxArgsSupported]bool

	out = &addKprobeOut{}

	loadProgName, loadProgRetName := kernels.GenericKprobeObjs()

	config := &api.EventConfig{}
	config.PolicyID = uint32(in.policyID)
	if len(f.ReturnArgAction) > 0 {
		if !kernels.EnableLargeProgs() {
			return nil, fmt.Errorf("ReturnArgAction requires kernel >=5.3")
		}
		config.ArgReturnAction = selectors.ActionTypeFromString(f.ReturnArgAction)
		if config.ArgReturnAction == selectors.ActionTypeInvalid {
			return nil, fmt.Errorf("ReturnArgAction type '%s' unsupported", f.ReturnArgAction)
		}
	}

	isSecurityFunc := strings.HasPrefix(funcName, "security_")

	if selectors.HasOverride(f) {
		if isSecurityFunc && in.useMulti {
			return nil, fmt.Errorf("Error: can't override '%s' function with kprobe_multi, use --disable-kprobe-multi option",
				funcName)
		}
		if isSecurityFunc && !bpf.HasModifyReturn() {
			return nil, fmt.Errorf("Error: can't override '%s' function without fmodret support",
				funcName)
		}
	}

	argRetprobe = nil // holds pointer to arg for return handler

	// Parse Arguments
	for j, a := range f.Args {
		argType := gt.GenericTypeFromString(a.Type)
		if argType == gt.GenericInvalidType {
			return nil, fmt.Errorf("Arg(%d) type '%s' unsupported", j, a.Type)
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
			return nil, err
		}
		if argReturnCopy(argMValue) {
			argRetprobe = &f.Args[j]
		}
		if a.Index > 4 {
			return nil,
				fmt.Errorf("Error add arg: ArgType %s Index %d out of bounds",
					a.Type, int(a.Index))
		}
		config.Arg[a.Index] = int32(argType)
		config.ArgM[a.Index] = uint32(argMValue)

		argsBTFSet[a.Index] = true
		argP := argPrinters{index: j, ty: argType, maxData: a.MaxData, label: a.Label}
		argSigPrinters = append(argSigPrinters, argP)
	}

	// Parse ReturnArg, we have two types of return arg parsing. We
	// support populating a kprobe buffer from kretprobe hooks. This
	// is used to capture data that is populated by the function hoooked.
	// For example Read calls supply a buffer to the syscall, but we
	// wont have its contents until kretprobe is run. The other type is
	// the f.Return case. These capture the return value of the function
	// without context from the kprobe hook. The BTF argument 'argreturn'
	// instructs the BPF kretprobe program which type of copy to use. And
	// argReturnPrinters tell golang printer piece how to print the event.
	if f.Return {
		if f.ReturnArg == nil {
			return nil, fmt.Errorf("ReturnArg not specified with Return=true")
		}
		argType := gt.GenericTypeFromString(f.ReturnArg.Type)
		if argType == gt.GenericInvalidType {
			if f.ReturnArg.Type == "" {
				return nil, fmt.Errorf("ReturnArg not specified with Return=true")
			}
			return nil, fmt.Errorf("ReturnArg type '%s' unsupported", f.ReturnArg.Type)
		}
		config.ArgReturn = int32(argType)
		argsBTFSet[api.ReturnArgIndex] = true
		argP := argPrinters{index: api.ReturnArgIndex, ty: argType}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		config.ArgReturn = int32(0)
	}

	if argRetprobe != nil {
		argsBTFSet[api.ReturnArgIndex] = true
		setRetprobe = true

		argType := gt.GenericTypeFromString(argRetprobe.Type)
		config.ArgReturnCopy = int32(argType)

		argP := argPrinters{index: int(argRetprobe.Index), ty: argType, label: argRetprobe.Label}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		config.ArgReturnCopy = int32(0)
	}

	// Mark remaining arguments as 'nops' the kernel side will skip
	// copying 'nop' args.
	for j, a := range argsBTFSet {
		if a == false {
			if j != api.ReturnArgIndex {
				config.Arg[j] = gt.GenericNopType
				config.ArgM[j] = 0
			}
		}
	}

	// Copy over userspace return filters
	var userReturnFilters []v1alpha1.ArgSelector
	for _, s := range f.Selectors {
		for _, returnArg := range s.MatchReturnArgs {
			// we allow integer values so far
			for _, v := range returnArg.Values {
				if _, err := strconv.Atoi(v); err != nil {
					return nil, fmt.Errorf("ReturnArg value supports only integer values, got %s", v)
				}
			}
			// only single value for GT,LT operators
			if isGTOperator(returnArg.Operator) || isLTOperator(returnArg.Operator) {
				if len(returnArg.Values) > 1 {
					return nil, fmt.Errorf("ReturnArg operater '%s' supports only single value, got %d",
						returnArg.Operator, len(returnArg.Values))
				}
			}
			userReturnFilters = append(userReturnFilters, returnArg)
		}
	}

	// Write attributes into BTF ptr for use with load
	if !setRetprobe {
		setRetprobe = f.Return
	}

	if f.Syscall {
		config.Syscall = 1
	} else {
		config.Syscall = 0
	}

	if selectors.HasEarlyBinaryFilter(f.Selectors) {
		config.Flags |= flagsEarlyFilter
	}

	// create a new entry on the table, and pass its id to BPF-side
	// so that we can do the matching at event-generation time
	kprobeEntry := genericKprobe{
		loadArgs: kprobeLoadArgs{
			retprobe: setRetprobe,
			syscall:  f.Syscall,
			config:   config,
		},
		argSigPrinters:    argSigPrinters,
		argReturnPrinters: argReturnPrinters,
		userReturnFilters: userReturnFilters,
		funcName:          funcName,
		pendingEvents:     nil,
		tableId:           idtable.UninitializedEntryID,
		policyName:        in.policyName,
		hasOverride:       selectors.HasOverride(f),
		customHandler:     in.customHandler,
	}

	// Parse Filters into kernel filter logic
	kprobeEntry.loadArgs.selectors, err = selectors.InitKernelSelectorState(f.Selectors, f.Args, &kprobeEntry.actionArgs, nil, selMaps)
	if err != nil {
		return nil, err
	}

	kprobeEntry.pendingEvents, err = lru.New[pendingEventKey, pendingEvent](4096)
	if err != nil {
		return nil, err
	}

	genericKprobeTable.AddEntry(&kprobeEntry)
	tidx := kprobeEntry.tableId.ID
	out.tableEntryIndex = tidx
	config.FuncId = uint32(tidx)

	if in.useMulti {
		kprobeEntry.pinPathPrefix = multiKprobePinPath(in.sensorPath)
		if setRetprobe {
			out.multiRetIDs = append(out.multiRetIDs, kprobeEntry.tableId)
		}
		out.multiIDs = append(out.multiIDs, kprobeEntry.tableId)
		logger.GetLogger().
			WithField("return", setRetprobe).
			WithField("function", kprobeEntry.funcName).
			WithField("override", kprobeEntry.hasOverride).
			Infof("Added multi kprobe")
		return out, nil
	}

	kprobeEntry.pinPathPrefix = sensors.PathJoin(in.sensorPath, fmt.Sprintf("gkp-%d", tidx))
	pinPath := kprobeEntry.pinPathPrefix
	pinProg := sensors.PathJoin(pinPath, fmt.Sprintf("%s_prog", kprobeEntry.funcName))

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		funcName,
		"kprobe/generic_kprobe",
		pinProg,
		"generic_kprobe").
		SetLoaderData(kprobeEntry.tableId)
	load.Override = kprobeEntry.hasOverride
	if load.Override {
		load.OverrideFmodRet = isSecurityFunc && bpf.HasModifyReturn()
	}
	out.progs = append(out.progs, load)

	fdinstall := program.MapBuilderPin("fdinstall_map", sensors.PathJoin(in.sensorPath, "fdinstall_map"), load)
	out.maps = append(out.maps, fdinstall)

	configMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "config_map"), load)
	out.maps = append(out.maps, configMap)

	tailCalls := program.MapBuilderPin("kprobe_calls", sensors.PathJoin(pinPath, "kp_calls"), load)
	out.maps = append(out.maps, tailCalls)

	filterMap := program.MapBuilderPin("filter_map", sensors.PathJoin(pinPath, "filter_map"), load)
	out.maps = append(out.maps, filterMap)

	argFilterMaps := program.MapBuilderPin("argfilter_maps", sensors.PathJoin(pinPath, "argfilter_maps"), load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := kprobeEntry.loadArgs.selectors.ValueMapsMaxEntries()
		argFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	out.maps = append(out.maps, argFilterMaps)

	addr4FilterMaps := program.MapBuilderPin("addr4lpm_maps", sensors.PathJoin(pinPath, "addr4lpm_maps"), load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := kprobeEntry.loadArgs.selectors.Addr4MapsMaxEntries()
		addr4FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	out.maps = append(out.maps, addr4FilterMaps)

	addr6FilterMaps := program.MapBuilderPin("addr6lpm_maps", sensors.PathJoin(pinPath, "addr6lpm_maps"), load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := kprobeEntry.loadArgs.selectors.Addr6MapsMaxEntries()
		addr6FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	out.maps = append(out.maps, addr6FilterMaps)

	var stringFilterMap [selectors.StringMapsNumSubMaps]*program.Map
	for string_map_index := 0; string_map_index < selectors.StringMapsNumSubMaps; string_map_index++ {
		stringFilterMap[string_map_index] = program.MapBuilderPin(fmt.Sprintf("string_maps_%d", string_map_index),
			sensors.PathJoin(pinPath, fmt.Sprintf("string_maps_%d", string_map_index)), load)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := kprobeEntry.loadArgs.selectors.StringMapsMaxEntries(string_map_index)
			stringFilterMap[string_map_index].SetInnerMaxEntries(maxEntries)
		}
		out.maps = append(out.maps, stringFilterMap[string_map_index])
	}

	stringPrefixFilterMaps := program.MapBuilderPin("string_prefix_maps", sensors.PathJoin(pinPath, "string_prefix_maps"), load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := kprobeEntry.loadArgs.selectors.StringPrefixMapsMaxEntries()
		stringPrefixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	out.maps = append(out.maps, stringPrefixFilterMaps)

	stringPostfixFilterMaps := program.MapBuilderPin("string_postfix_maps", sensors.PathJoin(pinPath, "string_postfix_maps"), load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := kprobeEntry.loadArgs.selectors.StringPostfixMapsMaxEntries()
		stringPostfixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	out.maps = append(out.maps, stringPostfixFilterMaps)

	retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), load)
	out.maps = append(out.maps, retProbe)

	callHeap := program.MapBuilderPin("process_call_heap", sensors.PathJoin(pinPath, "process_call_heap"), load)
	out.maps = append(out.maps, callHeap)

	selNamesMap := program.MapBuilderPin("sel_names_map", sensors.PathJoin(pinPath, "sel_names_map"), load)
	out.maps = append(out.maps, selNamesMap)

	stackTraceMap := program.MapBuilderPin("stack_trace_map", sensors.PathJoin(pinPath, "stack_trace_map"), load)
	out.maps = append(out.maps, stackTraceMap)

	if kernels.EnableLargeProgs() {
		socktrack := program.MapBuilderPin("socktrack_map", sensors.PathJoin(in.sensorPath, "socktrack_map"), load)
		out.maps = append(out.maps, socktrack)
	}

	if setRetprobe {
		pinRetProg := sensors.PathJoin(pinPath, fmt.Sprintf("%s_ret_prog", kprobeEntry.funcName))
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			funcName,
			"kprobe/generic_retkprobe",
			pinRetProg,
			"generic_kprobe").
			SetRetProbe(true).
			SetLoaderData(kprobeEntry.tableId)
		out.progs = append(out.progs, loadret)

		retProbe := program.MapBuilderPin("retprobe_map", sensors.PathJoin(pinPath, "retprobe_map"), loadret)
		out.maps = append(out.maps, retProbe)

		retConfigMap := program.MapBuilderPin("config_map", sensors.PathJoin(pinPath, "retprobe_config_map"), loadret)
		out.maps = append(out.maps, retConfigMap)

		// add maps with non-default paths (pins) to the retprobe
		program.MapBuilderPin("process_call_heap", sensors.PathJoin(pinPath, "process_call_heap"), loadret)
		program.MapBuilderPin("fdinstall_map", sensors.PathJoin(in.sensorPath, "fdinstall_map"), loadret)
		if kernels.EnableLargeProgs() {
			program.MapBuilderPin("socktrack_map", sensors.PathJoin(in.sensorPath, "socktrack_map"), loadret)
		}
	}

	logger.GetLogger().WithField("flags", flagsString(config.Flags)).
		WithField("override", kprobeEntry.hasOverride).
		Infof("Added generic kprobe sensor: %s -> %s", load.Name, load.Attach)
	return out, nil
}

func loadSingleKprobeSensor(id idtable.EntryID, bpfDir, mapDir string, load *program.Program, verbose int) error {
	gk, err := genericKprobeTableGet(id)
	if err != nil {
		return err
	}

	if !load.RetProbe {
		load.MapLoad = append(load.MapLoad, selectorsMaploads(gk.loadArgs.selectors, gk.pinPathPrefix, 0)...)
	}

	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, gk.loadArgs.config)
	config := &program.MapLoad{
		Index: 0,
		Name:  "config_map",
		Load: func(m *ebpf.Map, index uint32) error {
			return m.Update(index, configData.Bytes()[:], ebpf.UpdateAny)
		},
	}
	load.MapLoad = append(load.MapLoad, config)

	if err := program.LoadKprobeProgram(bpfDir, mapDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe program: %s -> %s", load.Name, load.Attach)
	} else {
		return err
	}

	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, base.NamesMap.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	for i, path := range gk.loadArgs.selectors.GetNewBinaryMappings() {
		writeBinaryMap(m, i, path)
	}

	return err
}

func loadMultiKprobeSensor(ids []idtable.EntryID, bpfDir, mapDir string, load *program.Program, verbose int) error {
	bin_buf := make([]bytes.Buffer, len(ids))

	data := &program.MultiKprobeAttachData{}

	for index, id := range ids {
		gk, err := genericKprobeTableGet(id)
		if err != nil {
			return err
		}

		if !load.RetProbe {
			load.MapLoad = append(load.MapLoad, selectorsMaploads(gk.loadArgs.selectors, gk.pinPathPrefix, uint32(index))...)
		}

		binary.Write(&bin_buf[index], binary.LittleEndian, gk.loadArgs.config)
		config := &program.MapLoad{
			Index: uint32(index),
			Name:  "config_map",
			Load: func(m *ebpf.Map, index uint32) error {
				return m.Update(index, bin_buf[index].Bytes()[:], ebpf.UpdateAny)
			},
		}
		load.MapLoad = append(load.MapLoad, config)

		data.Symbols = append(data.Symbols, gk.funcName)
		data.Cookies = append(data.Cookies, uint64(index))

		if gk.hasOverride && !load.RetProbe {
			data.Overrides = append(data.Overrides, gk.funcName)
		}
	}

	load.Override = len(data.Overrides) > 0
	load.OverrideFmodRet = false
	load.SetAttachData(data)

	if err := program.LoadMultiKprobeProgram(bpfDir, mapDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe sensor: %s -> %s", load.Name, load.Attach)
	} else {
		return err
	}

	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, base.NamesMap.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	for _, id := range ids {
		if gk, err := genericKprobeTableGet(id); err == nil {
			for i, path := range gk.loadArgs.selectors.GetNewBinaryMappings() {
				writeBinaryMap(m, i, path)
			}
		}
	}

	return err
}

func loadGenericKprobeSensor(bpfDir, mapDir string, load *program.Program, verbose int) error {
	if id, ok := load.LoaderData.(idtable.EntryID); ok {
		return loadSingleKprobeSensor(id, bpfDir, mapDir, load, verbose)
	}
	if ids, ok := load.LoaderData.([]idtable.EntryID); ok {
		return loadMultiKprobeSensor(ids, bpfDir, mapDir, load, verbose)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}

var errParseStringSize = errors.New("error parsing string size from binary")

// this is from bpf/process/types/basic.h 'MAX_STRING'
const maxStringSize = 1024

// parseString parses strings encoded from BPF copy_strings in the form:
// *---------*---------*
// | 4 bytes | N bytes |
// |  size   | string  |
// *---------*---------*
func parseString(r io.Reader) (string, error) {
	var size int32
	err := binary.Read(r, binary.LittleEndian, &size)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errParseStringSize, err)
	}

	if size < 0 {
		return "", errors.New("string size is negative")
	}

	// limit the size of the string to avoid huge memory allocation and OOM kill in case of issue
	if size > maxStringSize {
		return "", fmt.Errorf("string size too large: %d, max size is %d", size, maxStringSize)
	}
	stringBuffer := make([]byte, size)
	err = binary.Read(r, binary.LittleEndian, &stringBuffer)
	if err != nil {
		return "", fmt.Errorf("error parsing string from binary with size %d: %s", size, err)
	}

	// remove the trailing '\0' from the C string
	if len(stringBuffer) > 0 && stringBuffer[len(stringBuffer)-1] == '\x00' {
		stringBuffer = stringBuffer[:len(stringBuffer)-1]
	}

	return strutils.UTF8FromBPFBytes(stringBuffer), nil
}

func convertKernelDeviceToUser(kd uint32) uint32 {
	major := kd >> 20
	minor := kd & 0xfffff
	return (minor & 0xff) | (major << 8) | ((minor & 0xfff00) << 12)
}

func ReadArgBytes(r *bytes.Reader, index int, hasMaxData bool) (*api.MsgGenericKprobeArgBytes, error) {
	var bytes, bytes_rd, hasDataEvents int32
	var arg api.MsgGenericKprobeArgBytes

	if hasMaxData {
		/* First int32 indicates if data events are used (1) or not (0). */
		if err := binary.Read(r, binary.LittleEndian, &hasDataEvents); err != nil {
			return nil, fmt.Errorf("failed to read original size for buffer argument: %w", err)
		}
		if hasDataEvents != 0 {
			var desc dataapi.DataEventDesc

			if err := binary.Read(r, binary.LittleEndian, &desc); err != nil {
				return nil, err
			}
			data, err := observer.DataGet(desc)
			if err != nil {
				return nil, err
			}
			arg.Index = uint64(index)
			arg.OrigSize = uint64(len(data) + int(desc.Leftover))
			arg.Value = data
			return &arg, nil
		}
	}

	if err := binary.Read(r, binary.LittleEndian, &bytes); err != nil {
		return nil, fmt.Errorf("failed to read original size for buffer argument: %w", err)
	}

	arg.Index = uint64(index)
	if bytes == CharBufSavedForRetprobe {
		return &arg, nil
	}
	// bpf-side returned an error
	if bytes < 0 {
		// NB: once we extended arguments to also pass errors, we can change
		// this.
		arg.Value = []byte(kprobeCharBufErrorToString(bytes))
		return &arg, nil
	}
	arg.OrigSize = uint64(bytes)
	if err := binary.Read(r, binary.LittleEndian, &bytes_rd); err != nil {
		return nil, fmt.Errorf("failed to read size for buffer argument: %w", err)
	}

	if bytes_rd > 0 {
		arg.Value = make([]byte, bytes_rd)
		if err := binary.Read(r, binary.LittleEndian, &arg.Value); err != nil {
			return nil, fmt.Errorf("failed to read buffer (size: %d): %w", bytes_rd, err)
		}
	}

	// NB: there are cases (e.g., read()) where it is valid to have an
	// empty (zero-length) buffer.
	return &arg, nil

}

func getUrl(url string) {
	// We fire and forget URLs, and we don't care if they hit or not.
	http.Get(url)
}

func dnsLookup(fqdn string) {
	// We fire and forget DNS lookups, and we don't care if they hit or not.
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dial := net.Dialer{}
			return dial.Dial("udp", "1.1.1.1:53")
		},
	}
	res.LookupIP(context.Background(), "ip4", fqdn)
}

func handleGenericKprobe(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	gk, err := genericKprobeTableGet(idtable.EntryID{ID: int(m.FuncId)})
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to match id:%d", m.FuncId)
		return nil, fmt.Errorf("Failed to match id")
	}

	ret, err := handleMsgGenericKprobe(&m, gk, r)
	if gk.customHandler != nil {
		ret, err = gk.customHandler(ret, err)
	}
	return ret, err
}

func handleMsgGenericKprobe(m *api.MsgGenericKprobe, gk *genericKprobe, r *bytes.Reader) ([]observer.Event, error) {
	var err error

	switch m.ActionId {
	case selectors.ActionTypeGetUrl, selectors.ActionTypeDnsLookup:
		actionArgEntry, err := gk.actionArgs.GetEntry(idtable.EntryID{ID: int(m.ActionArgId)})
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

	unix := &tracing.MsgGenericKprobeUnix{}
	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Id = m.FuncId
	unix.Action = m.ActionId
	unix.Tid = m.Tid
	unix.FuncName = gk.funcName
	unix.Namespaces = m.Namespaces
	unix.Capabilities = m.Capabilities
	unix.PolicyName = gk.policyName

	returnEvent := m.Common.Flags&processapi.MSG_COMMON_FLAG_RETURN != 0

	var ktimeEnter uint64
	var printers []argPrinters
	if returnEvent {
		// if this a return event, also read the ktime of the enter event
		err := binary.Read(r, binary.LittleEndian, &ktimeEnter)
		if err != nil {
			return nil, fmt.Errorf("failed to read ktimeEnter")
		}
		printers = gk.argReturnPrinters
	} else {
		ktimeEnter = m.Common.Ktime
		printers = gk.argSigPrinters
	}

	if m.Common.Flags&processapi.MSG_COMMON_FLAG_STACKTRACE != 0 {
		if m.StackID < 0 {
			logger.GetLogger().Warnf("failed to retrieve stacktrace: id equal to errno %d", m.StackID)
		} else {
			// remove the error part
			id := uint32(m.StackID)

			// lazy load the map reference if needed
			if gk.stackTraceMapRef == nil {
				bpf.MapPrefixPath()
				gk.stackTraceMapRef, err = ebpf.LoadPinnedMap(path.Join(bpf.MapPrefixPath(), gk.pinPathPrefix)+"-stack_trace_map", &ebpf.LoadPinOptions{
					ReadOnly: true,
				})
				if err != nil {
					logger.GetLogger().WithError(err).Warn("failed to load the stacktrace map")
				}
				// close this in cleanup postHook defer stackTraceMap.Close()
			}

			// this can't be an else statement in the previous block since it
			// must execute as well when the reference is first initialized
			if gk.stackTraceMapRef != nil {
				err = gk.stackTraceMapRef.Lookup(id, &unix.StackTrace)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("failed to lookup the stacktrace map")
				}
			}
		}
	}

	for _, a := range printers {
		switch a.ty {
		case gt.GenericIntType, gt.GenericS32Type:
			var output int32
			var arg api.MsgGenericKprobeArgInt

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Int type error")
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericFileType, gt.GenericFdType, gt.GenericKiocb:
			var arg api.MsgGenericKprobeArgFile
			var flags uint32
			var b int32
			var kernelDevice uint32

			/* Eat file descriptor its not used in userland */
			if a.ty == gt.GenericFdType {
				binary.Read(r, binary.LittleEndian, &b)
			}

			arg.Index = uint64(a.index)

			err := binary.Read(r, binary.LittleEndian, &arg.Inode)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("error parsing inode of file")
			}

			err = binary.Read(r, binary.LittleEndian, &kernelDevice)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("error parsing device of file")
			}
			arg.Device = convertKernelDeviceToUser(kernelDevice)

			arg.Value, err = parseString(r)
			if err != nil {
				if errors.Is(err, errParseStringSize) {
					// If no size then path walk was not possible and file was
					// either a mount point or not a "file" at all which can
					// happen if running without any filters and kernel opens an
					// anonymous inode. For this lets just report its on "/" all
					// though pid filtering will mostly catch this.
					arg.Value = "/"
				} else {
					logger.GetLogger().WithError(err).Warn("error parsing arg type file")
				}
			}

			// read the first byte that keeps the flags
			err = binary.Read(r, binary.LittleEndian, &flags)
			if err != nil {
				flags = 0
			}

			arg.Flags = flags
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericPathType:
			var arg api.MsgGenericKprobeArgPath
			var flags uint32
			var kernelDevice uint32

			arg.Index = uint64(a.index)

			err := binary.Read(r, binary.LittleEndian, &arg.Inode)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("error parsing inode of file")
			}

			err = binary.Read(r, binary.LittleEndian, &kernelDevice)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("error parsing device of file")
			}
			arg.Device = convertKernelDeviceToUser(kernelDevice)

			arg.Value, err = parseString(r)
			if err != nil {
				if errors.Is(err, errParseStringSize) {
					arg.Value = "/"
				} else {
					logger.GetLogger().WithError(err).Warn("error parsing arg type path")
				}
			}

			// read the first byte that keeps the flags
			err = binary.Read(r, binary.LittleEndian, &flags)
			if err != nil {
				flags = 0
			}

			arg.Flags = flags
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericFilenameType, gt.GenericStringType:
			var arg api.MsgGenericKprobeArgString

			arg.Index = uint64(a.index)
			arg.Value, err = parseString(r)
			if err != nil {
				logger.GetLogger().WithError(err).Warn("error parsing arg type string")
			}

			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericCredType:
			var cred api.MsgGenericCred
			var arg api.MsgGenericKprobeArgCred

			err := binary.Read(r, binary.LittleEndian, &cred)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("cred type err")
			}

			arg.Index = uint64(a.index)
			arg.Uid = cred.Uid
			arg.Gid = cred.Gid
			arg.Suid = cred.Suid
			arg.Sgid = cred.Sgid
			arg.Euid = cred.Euid
			arg.Egid = cred.Egid
			arg.FSuid = cred.FSuid
			arg.FSgid = cred.FSgid
			arg.SecureBits = cred.SecureBits
			arg.Cap.Permitted = cred.Cap.Permitted
			arg.Cap.Effective = cred.Cap.Effective
			arg.Cap.Inheritable = cred.Cap.Inheritable
			arg.UserNs.Level = cred.UserNs.Level
			arg.UserNs.Uid = cred.UserNs.Uid
			arg.UserNs.Gid = cred.UserNs.Gid
			arg.UserNs.NsInum = cred.UserNs.NsInum
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericCharBuffer, gt.GenericCharIovec, gt.GenericIovIter:
			if arg, err := ReadArgBytes(r, a.index, a.maxData); err == nil {
				arg.Label = a.label
				unix.Args = append(unix.Args, *arg)
			} else {
				logger.GetLogger().WithError(err).Warnf("failed to read bytes argument")
			}
		case gt.GenericSkbType:
			var skb api.MsgGenericKprobeSkb
			var arg api.MsgGenericKprobeArgSkb

			err := binary.Read(r, binary.LittleEndian, &skb)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("skb type err")
			}

			arg.Index = uint64(a.index)
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
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericSockType:
			var sock api.MsgGenericKprobeSock
			var arg api.MsgGenericKprobeArgSock

			err := binary.Read(r, binary.LittleEndian, &sock)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("sock type err")
			}

			arg.Index = uint64(a.index)
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
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericSizeType, gt.GenericU64Type:
			var output uint64
			var arg api.MsgGenericKprobeArgSize

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericNopType:
			// do nothing
		case gt.GenericBpfAttr:
			var output api.MsgGenericKprobeBpfAttr
			var arg api.MsgGenericKprobeArgBpfAttr

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("bpf_attr type error")
			}
			arg.ProgType = output.ProgType
			arg.InsnCnt = output.InsnCnt
			length := bytes.IndexByte(output.ProgName[:], 0) // trim tailing null bytes
			arg.ProgName = string(output.ProgName[:length])
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericPerfEvent:
			var output api.MsgGenericKprobePerfEvent
			var arg api.MsgGenericKprobeArgPerfEvent

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("perf_event type error")
			}
			length := bytes.IndexByte(output.KprobeFunc[:], 0) // trim tailing null bytes
			arg.KprobeFunc = string(output.KprobeFunc[:length])
			arg.Type = output.Type
			arg.Config = output.Config
			arg.ProbeOffset = output.ProbeOffset
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericBpfMap:
			var output api.MsgGenericKprobeBpfMap
			var arg api.MsgGenericKprobeArgBpfMap

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("bpf_map type error")
			}

			arg.MapType = output.MapType
			arg.KeySize = output.KeySize
			arg.ValueSize = output.ValueSize
			arg.MaxEntries = output.MaxEntries
			length := bytes.IndexByte(output.MapName[:], 0) // trim tailing null bytes
			arg.MapName = string(output.MapName[:length])
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericU32Type:
			var output uint32
			var arg api.MsgGenericKprobeArgUInt

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("UInt type error")
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericUserNamespace:
			var output api.MsgGenericUserNamespace
			var arg api.MsgGenericKprobeArgUserNamespace

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("user_namespace type error")
			}
			arg.Level = output.Level
			arg.Uid = output.Uid
			arg.Gid = output.Gid
			arg.NsInum = output.NsInum
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericCapability:
			var output api.MsgGenericKprobeCapability
			var arg api.MsgGenericKprobeArgCapability

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("capability type error")
			}
			arg.Value = output.Value
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericLoadModule:
			var output api.MsgGenericLoadModule
			var arg api.MsgGenericKprobeArgLoadModule

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("load_module type error")
			} else if output.Name[0] != 0x00 {
				i := bytes.IndexByte(output.Name[:api.MODULE_NAME_LEN], 0)
				if i == -1 {
					i = api.MODULE_NAME_LEN
				}
				arg.Name = string(output.Name[:i])
				arg.SigOk = output.SigOk
				arg.Taints = output.Taints
			}
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		case gt.GenericKernelModule:
			var output api.MsgGenericLoadModule
			var arg api.MsgGenericKprobeArgKernelModule

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("kernel module type error")
			} else if output.Name[0] != 0x00 {
				i := bytes.IndexByte(output.Name[:api.MODULE_NAME_LEN], 0)
				if i == -1 {
					i = api.MODULE_NAME_LEN
				}
				arg.Name = string(output.Name[:i])
				arg.Taints = output.Taints
			}
			arg.Label = a.label
			unix.Args = append(unix.Args, arg)
		default:
			logger.GetLogger().WithError(err).WithField("event-type", a.ty).Warnf("Unknown event type")
		}
	}

	// Cache return value on merge and run return filters below before
	// passing up to notify hooks.
	var retArg *api.MsgGenericKprobeArg

	// there are two events for this probe (entry and return)
	if gk.loadArgs.retprobe {
		// if an event exist already, try to merge them. Otherwise, add
		// the one we have in the map.
		curr := pendingEvent{ev: unix, returnEvent: returnEvent}
		key := pendingEventKey{eventId: m.RetProbeId, ktimeEnter: ktimeEnter}

		if prev, exists := gk.pendingEvents.Get(key); exists {
			gk.pendingEvents.Remove(key)
			unix, retArg = retprobeMerge(prev, curr)
		} else {
			gk.pendingEvents.Add(key, curr)
			kprobemetrics.MergePushedInc()
			unix = nil
		}
	}
	if unix == nil {
		return []observer.Event{}, err
	}
	// Last layer of filtering done before Notify upper layers. This is
	// needed for filters and actions that can't be committed in kernel
	// space. For example if we simply dropped a return arg because of
	// a filter we wouldn't be able to cleanup initial event from entry.
	// Alternatively, some actions have no kernel analog, such as pause
	// pod.
	if filterReturnArg(gk.userReturnFilters, retArg) {
		return []observer.Event{}, err
	}

	return []observer.Event{unix}, err
}

func filterReturnArg(userReturnFilters []v1alpha1.ArgSelector, retArg *api.MsgGenericKprobeArg) bool {
	// Short circuit, returnFilter indicates we should eat this event.
	if retArg == nil {
		return false
	}

	// If no filters are specified default to allow.
	if len(userReturnFilters) == 0 {
		return false
	}

	// Multiple selectors will be logical OR together.
	for _, uFilter := range userReturnFilters {
		// MatchPIDs only supported in kernel space because we have
		// full support back to 4.14 kernels.

		// MatchArgs handlers, uFilters only necessary for return
		// arg filters at the moment. Also we simply assume its an
		// int which is naive, but good enough someone should devote
		// more time to make this amazing tech(tm).
		switch uFilter.Operator {
		case "Equal":
			// If retarg Equals any value in the set {Values} accept event
			for _, v := range uFilter.Values {
				if vint, err := strconv.Atoi(v); err == nil {
					switch compare := (*retArg).(type) {
					case api.MsgGenericKprobeArgInt:
						if vint == int(compare.Value) {
							return false
						}
					}
				}
			}
		case "NotEqual":
			inSet := false
			for _, v := range uFilter.Values {
				if vint, err := strconv.Atoi(v); err == nil {
					switch compare := (*retArg).(type) {
					case api.MsgGenericKprobeArgInt:
						if vint == int(compare.Value) {
							inSet = true
						}
					}
				}
			}
			// If retarg was not in set {Values} accept event
			if !inSet {
				return false
			}
		}
		if isGTOperator(uFilter.Operator) {
			for _, v := range uFilter.Values {
				if vint, err := strconv.Atoi(v); err == nil {
					switch compare := (*retArg).(type) {
					case api.MsgGenericKprobeArgInt:
						if vint < int(compare.Value) {
							return false
						}
					}
				}
			}
		}
		if isLTOperator(uFilter.Operator) {
			for _, v := range uFilter.Values {
				if vint, err := strconv.Atoi(v); err == nil {
					switch compare := (*retArg).(type) {
					case api.MsgGenericKprobeArgInt:
						if vint > int(compare.Value) {
							return false
						}
					}
				}
			}
		}
	}
	// We walked all selectors and no selectors matched, eat the event.
	return true
}

func reportMergeError(curr pendingEvent, prev pendingEvent) {
	currFn := "UNKNOWN"
	if curr.ev != nil {
		currFn = curr.ev.FuncName
	}
	currType := "enter"
	if curr.returnEvent {
		currType = "exit"
	}

	prevFn := "UNKNOWN"
	if prev.ev != nil {
		prevFn = prev.ev.FuncName
	}
	prevType := "enter"
	if prev.returnEvent {
		prevType = "exit"
	}

	kprobemetrics.MergeErrorsInc(currFn, currType, prevFn, prevType)
	logger.GetLogger().WithFields(logrus.Fields{
		"currFn":   currFn,
		"currType": currType,
		"prevFn":   prevFn,
		"prevType": prevType,
	}).Debugf("failed to merge events")
}

// retprobeMerge merges the two events: the one from the entry probe with the one from the return probe
func retprobeMerge(prev pendingEvent, curr pendingEvent) (*tracing.MsgGenericKprobeUnix, *api.MsgGenericKprobeArg) {
	var retEv, enterEv *tracing.MsgGenericKprobeUnix
	var ret *api.MsgGenericKprobeArg

	if prev.returnEvent && !curr.returnEvent {
		retEv = prev.ev
		enterEv = curr.ev
	} else if !prev.returnEvent && curr.returnEvent {
		retEv = curr.ev
		enterEv = prev.ev
	} else {
		reportMergeError(curr, prev)
		return nil, nil
	}

	kprobemetrics.MergeOkTotalInc()

	for _, retArg := range retEv.Args {
		index := retArg.GetIndex()
		if uint64(len(enterEv.Args)) > index {
			enterEv.Args[index] = retArg
		} else {
			enterEv.Args = append(enterEv.Args, retArg)
			ret = &retArg
		}
	}
	return enterEv, ret
}

func (k *observerKprobeSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadGenericKprobeSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)
}
