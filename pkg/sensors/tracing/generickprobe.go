// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"runtime"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	ciliumbtf "github.com/cilium/ebpf/btf"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/asm"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"

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

type kprobeSelectors struct {
	entry *selectors.KernelSelectorState
	retrn *selectors.KernelSelectorState
}

type kprobeLoadArgs struct {
	selectors kprobeSelectors
	retprobe  bool
	syscall   bool
	config    *api.EventConfig
}

type pendingEventKey struct {
	eventId    uint64
	ktimeEnter uint64
}

type genericKprobeData struct {
	// stackTraceMap reference is needed when retrieving stack traces from
	// userspace when receiving events containing stacktrace IDs
	stackTraceMap *program.Map
}

// internal genericKprobe info
type genericKprobe struct {
	loadArgs          kprobeLoadArgs
	argSigPrinters    []argPrinter
	argReturnPrinters []argPrinter
	funcName          string
	instance          int

	// for kprobes that have a retprobe, we maintain the enter events in
	// the map, so that we can merge them when the return event is
	// generated. The events are maintained in the map below, using
	// the retprobe_id (thread_id) and the enter ktime as the key.
	pendingEvents *lru.Cache[pendingEventKey, pendingEvent[*tracing.MsgGenericKprobeUnix]]

	tableId idtable.EntryID

	// for kprobes that have a GetUrl or DnsLookup action, we store the table of arguments.
	actionArgs idtable.Table

	// policyName is the name of the policy that this tracepoint belongs to
	policyName string

	// message field of the Tracing Policy
	message string

	// tags field of the Tracing Policy
	tags []string

	// is there override defined for the kprobe
	hasOverride bool

	// sensor specific data that we need when we process event, so it's
	// unique for each kprobeEntry when we use single kprobes and it's
	// ont global instance when we use kprobe multi
	data *genericKprobeData

	// Does this kprobe is using stacktraces? Note that as specified in the
	// above data field comment, the map is global for multikprobe and unique
	// for each kprobe when using single kprobes.
	hasStackTrace bool

	customHandler eventhandler.Handler
}

// pendingEvent is an event waiting to be merged with another event.
// This is needed for retprobe probes that generate two events: one at the
// function entry, and one at the function return. We merge these events into
// one, before returning it to the user.
type pendingEvent[T evArgsRetriever] struct {
	ev          T
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

func getProgramSelector(load *program.Program, kprobeEntry *genericKprobe) *selectors.KernelSelectorState {
	if kprobeEntry != nil {
		if load.RetProbe {
			return kprobeEntry.loadArgs.selectors.retrn
		}
		return kprobeEntry.loadArgs.selectors.entry
	}
	return nil
}

func filterMaps(load *program.Program, kprobeEntry *genericKprobe) []*program.Map {
	var maps []*program.Map

	/*
	 * If we got passed genericKprobe != nil we can make selector map fixes
	 * related to the kernel version. We pass nil for multi kprobes but as
	 * they are added in later kernels than 5.9, there's no fixing needed.
	 */
	state := getProgramSelector(load, kprobeEntry)

	argFilterMaps := program.MapBuilderProgram("argfilter_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.ValueMapsMaxEntries()
		argFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, argFilterMaps)

	addr4FilterMaps := program.MapBuilderProgram("addr4lpm_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.Addr4MapsMaxEntries()
		addr4FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, addr4FilterMaps)

	addr6FilterMaps := program.MapBuilderProgram("addr6lpm_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.Addr6MapsMaxEntries()
		addr6FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, addr6FilterMaps)

	var stringFilterMap [selectors.StringMapsNumSubMaps]*program.Map
	numSubMaps := selectors.StringMapsNumSubMaps
	if !kernels.MinKernelVersion("5.11") {
		numSubMaps = selectors.StringMapsNumSubMapsSmall
	}

	for stringMapIndex := range numSubMaps {
		stringFilterMap[stringMapIndex] = program.MapBuilderProgram(fmt.Sprintf("string_maps_%d", stringMapIndex), load)
		if state != nil && !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := state.StringMapsMaxEntries(stringMapIndex)
			stringFilterMap[stringMapIndex].SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, stringFilterMap[stringMapIndex])
	}

	stringPrefixFilterMaps := program.MapBuilderProgram("string_prefix_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.StringPrefixMapsMaxEntries()
		stringPrefixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, stringPrefixFilterMaps)

	stringPostfixFilterMaps := program.MapBuilderProgram("string_postfix_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.StringPostfixMapsMaxEntries()
		stringPostfixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, stringPostfixFilterMaps)

	return maps
}

func createMultiKprobeSensor(polInfo *policyInfo, multiIDs []idtable.EntryID, has hasMaps) ([]*program.Program, []*program.Map, error) {
	var multiRetIDs []idtable.EntryID
	var progs []*program.Program
	var maps []*program.Map

	data := &genericKprobeData{}

	for _, id := range multiIDs {
		gk, err := genericKprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		if gk.loadArgs.retprobe {
			multiRetIDs = append(multiRetIDs, id)
		}
		gk.data = data

		has.stackTrace = has.stackTrace || gk.hasStackTrace
	}

	loadProgName, loadProgRetName := config.GenericKprobeObjs(true)

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("kprobe_multi (%d functions)", len(multiIDs)),
		"kprobe.multi/generic_kprobe",
		"multi_kprobe",
		"generic_kprobe").
		SetLoaderData(multiIDs).
		SetPolicy(polInfo.name)
	progs = append(progs, load)

	fdinstall := program.MapBuilderSensor("fdinstall_map", load)
	if has.fdInstall {
		fdinstall.SetMaxEntries(fdInstallMapMaxEntries)
	}
	maps = append(maps, fdinstall)

	configMap := program.MapBuilderProgram("config_map", load)
	maps = append(maps, configMap)

	tailCalls := program.MapBuilderProgram("kprobe_calls", load)
	maps = append(maps, tailCalls)

	filterMap := program.MapBuilderProgram("filter_map", load)
	maps = append(maps, filterMap)

	maps = append(maps, filterMaps(load, nil)...)

	retProbe := program.MapBuilderSensor("retprobe_map", load)
	maps = append(maps, retProbe)

	callHeap := program.MapBuilderSensor("process_call_heap", load)
	maps = append(maps, callHeap)

	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, selMatchBinariesMap)

	matchBinariesPaths := program.MapBuilderProgram("tg_mb_paths", load)
	maps = append(maps, matchBinariesPaths)

	stackTraceMap := program.MapBuilderProgram("stack_trace_map", load)
	if has.stackTrace {
		stackTraceMap.SetMaxEntries(stackTraceMapMaxEntries)
	}

	maps = append(maps, stackTraceMap)
	data.stackTraceMap = stackTraceMap

	if config.EnableLargeProgs() {
		socktrack := program.MapBuilderSensor("socktrack_map", load)
		if has.sockTrack {
			socktrack.SetMaxEntries(socktrackMapMaxEntries)
		}
		maps = append(maps, socktrack)
	}

	if config.EnableLargeProgs() {
		ratelimitMap := program.MapBuilderSensor("ratelimit_map", load)
		if has.rateLimit {
			ratelimitMap.SetMaxEntries(ratelimitMapMaxEntries)
		}
		maps = append(maps, ratelimitMap)
	}

	if has.enforcer {
		maps = append(maps, enforcerMapsUser(load)...)
	}

	if option.Config.EnableCgTrackerID {
		maps = append(maps, program.MapUser(cgtracker.MapName, load))
	}

	filterMap.SetMaxEntries(len(multiIDs))
	configMap.SetMaxEntries(len(multiIDs))

	overrideTasksMap := program.MapBuilderProgram("override_tasks", load)
	if has.override {
		overrideTasksMap.SetMaxEntries(overrideMapMaxEntries)
	}
	maps = append(maps, overrideTasksMap)

	maps = append(maps, polInfo.policyConfMap(load), polInfo.policyStatsMap(load))

	if len(multiRetIDs) != 0 {
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			fmt.Sprintf("%d retkprobes", len(multiIDs)),
			"kprobe.multi/generic_retkprobe",
			"multi_retkprobe",
			"generic_kprobe").
			SetRetProbe(true).
			SetLoaderData(multiRetIDs).
			SetPolicy(polInfo.name)
		progs = append(progs, loadret)

		retProbe := program.MapBuilderSensor("retprobe_map", loadret)
		maps = append(maps, retProbe)

		retConfigMap := program.MapBuilderProgram("config_map", loadret)
		maps = append(maps, retConfigMap)

		retFilterMap := program.MapBuilderProgram("filter_map", loadret)
		maps = append(maps, retFilterMap)

		maps = append(maps, filterMaps(loadret, nil)...)

		callHeap := program.MapBuilderSensor("process_call_heap", loadret)
		maps = append(maps, callHeap)

		fdinstall := program.MapBuilderSensor("fdinstall_map", loadret)
		if has.fdInstall {
			fdinstall.SetMaxEntries(fdInstallMapMaxEntries)
		}
		maps = append(maps, fdinstall)

		socktrack := program.MapBuilderSensor("socktrack_map", loadret)
		if has.sockTrack {
			socktrack.SetMaxEntries(socktrackMapMaxEntries)
		}
		maps = append(maps, socktrack)

		tailCalls := program.MapBuilderProgram("retkprobe_calls", loadret)
		maps = append(maps, tailCalls)

		retConfigMap.SetMaxEntries(len(multiRetIDs))
		retFilterMap.SetMaxEntries(len(multiRetIDs))
	}

	return progs, maps, nil
}

func validateKprobeType(ty string) error {
	invalidArgTypes := []string{"auto", "syscall64"}
	if slices.Contains(invalidArgTypes, ty) {
		return fmt.Errorf("type '%s' is invalid for kprobes", ty)
	}
	return nil
}

type kpValidateInfo struct {
	calls   []string
	syscall bool
	ignore  bool
}

func validateOverride(
	f *v1alpha1.KProbeSpec,
	funcName string,
	useMulti bool,
) error {
	isSecurityFunc := strings.HasPrefix(funcName, "security_")

	if isSecurityFunc {
		// LSM functions
		if !bpf.HasModifyReturn() {
			return errors.New("override action not supported on security_ hooks, fmod_ret not available")
		}

		if useMulti {
			return fmt.Errorf("can't override '%s' function with kprobe_multi, use --%s option", funcName, option.KeyDisableKprobeMulti)
		}
	} else if f.Syscall {
		if !bpf.HasOverrideHelper() {
			return errors.New("override action not supported on syscalls, bpf_override_return helper not available")
		}
	} else {
		return errors.New("override action can be used only with syscalls and security_ hooks")
	}

	return nil
}

func preValidateKprobe(
	log logger.FieldLogger,
	f *v1alpha1.KProbeSpec,
	ks *ksyms.Ksyms,
	btfobj *btf.Spec,
	lists []v1alpha1.ListSpec,
) (*kpValidateInfo, error) {
	isSyscall := f.Syscall
	var calls []string
	// the f.Call is either defined as list:NAME
	// or specifies directly the function
	if isL, list := isList(f.Call, lists); isL {
		if list == nil {
			return nil, fmt.Errorf("error list '%s' not found", f.Call)
		}
		var err error
		calls, err = getListSymbols(list)
		if err != nil {
			return nil, fmt.Errorf("failed to get symbols from list '%s': %w", f.Call, err)
		}
		if isSyscallListType(list.Type) {
			isSyscall = true
		}
	} else {
		calls = []string{f.Call}
		if f.Syscall {
			// modifying f.Call directly since BTF validation
			// later will use v1alpha1.KProbeSpec object
			prefixedName, err := arch.AddSyscallPrefix(f.Call)
			if err != nil {
				log.Warn("kprobe spec pre-validation of syscall prefix failed, continuing with original name", logfields.Error, err)
			} else {
				calls[0] = prefixedName
			}
		}
	}

	for sid, selector := range f.Selectors {
		for mid, matchAction := range selector.MatchActions {
			if (matchAction.KernelStackTrace || matchAction.UserStackTrace) && matchAction.Action != "Post" {
				return nil, fmt.Errorf("kernelStackTrace or userStackTrace can only be used along Post action: got (kernelStackTrace/userStackTrace) enabled in selectors[%d].matchActions[%d] with action '%s'", sid, mid, matchAction.Action)
			}
		}
	}

	if selectors.HasSigkillAction(f) && !config.EnableLargeProgs() {
		return nil, errors.New("sigkill action requires kernel >= 5.3.0")
	}

	retCalls := make([]string, 0, len(calls))
	ignored := 0
	for idx, call := range calls {
		var warn *btf.ValidationWarnError
		var failed *btf.ValidationFailedError

		// Now go over BTF validation
		err := btf.ValidateKprobeSpec(btfobj, call, f, ks)
		switch {
		case err == nil:
		case errors.As(err, &warn):
			log.Warn("kprobe spec pre-validation issued a warning, but will continue with loading", logfields.Error, warn)
		case errors.As(err, &failed):
			if f.Ignore != nil && f.Ignore.CallNotFound && errors.Is(err, ciliumbtf.ErrNotFound) {
				log.Info("kprobe call ignored because it was not found", "idx", idx, "call", call)
				ignored++
				continue
			}
			return nil, fmt.Errorf("kprobe spec pre-validation failed: %w", failed)
		default:
			log.Warn("kprobe spec pre-validation returned an error, but will continue with loading", logfields.Error, err)
		}
		retCalls = append(retCalls, call)
	}

	for idxArg, arg := range f.Args {
		if err := validateKprobeType(arg.Type); err != nil {
			return nil, fmt.Errorf("args[%d].type: %w", idxArg, err)
		}
	}

	return &kpValidateInfo{
		calls:   retCalls,
		syscall: isSyscall,
		ignore:  ignored == len(calls), // if all calls were ignored, ignore the whole kprobe
	}, nil
}

func allKprobesIgnored(info []*kpValidateInfo) bool {
	for _, i := range info {
		if !i.ignore {
			return false
		}
	}
	return true
}

// preValidateKprobes pre-validates the semantics and BTF information of a Kprobe spec
// Furthermore, it does some preprocessing of the calls and returns one kpValidateInfo struct per
// kprobe. It also validates that if any selector uses NotifyEnforcer action, the spec contains enforcers.
func preValidateKprobes(log logger.FieldLogger, kprobes []v1alpha1.KProbeSpec, lists []v1alpha1.ListSpec, enforcers []v1alpha1.EnforcerSpec) ([]*kpValidateInfo, error) {
	btfobj, err := btf.NewBTF()
	if err != nil {
		return nil, err
	}

	// validate lists first
	err = preValidateLists(lists)
	if err != nil {
		return nil, err
	}

	// get kernel symbols
	ks, err := ksyms.KernelSymbols()
	if err != nil {
		return nil, fmt.Errorf("validateKprobeSpec: ksyms.KernelSymbols: %w", err)
	}

	// If the NotifyEnforcer action is specified, there must be at least one enforcer.
	for _, kprobe := range kprobes {
		if selectors.HasNotifyEnforcerAction(&kprobe) {
			if len(enforcers) == 0 {
				return nil, errors.New("NotifyEnforcer action specified, but spec contains no enforcers")
			}
		}
	}

	ret := make([]*kpValidateInfo, len(kprobes))
	for i := range kprobes {
		var err error
		ret[i], err = preValidateKprobe(log, &kprobes[i], ks, btfobj, lists)
		if err != nil {
			return nil, fmt.Errorf("error in spec.kprobes[%d]: %w", i, err)
		}
	}

	return ret, nil
}

type addKprobeIn struct {
	useMulti      bool
	sensorPath    string
	policyName    string
	policyID      policyfilter.PolicyID
	customHandler eventhandler.Handler
	selMaps       *selectors.KernelSelectorMaps
}

type hasMaps struct {
	stackTrace bool
	rateLimit  bool
	fdInstall  bool
	enforcer   bool
	override   bool
	sockTrack  bool
}

// hasMapsSetup setups the has maps for the per policy maps. The per kprobe maps
// are setup later in createSingleKprobeSensor or createMultiKprobeSensor.
func hasMapsSetup(spec *v1alpha1.TracingPolicySpec) hasMaps {
	has := hasMaps{}
	for _, kprobe := range spec.KProbes {
		has.fdInstall = has.fdInstall || selectors.HasFDInstall(kprobe.Selectors)
		has.enforcer = has.enforcer || len(spec.Enforcers) != 0
		has.rateLimit = has.rateLimit || selectors.HasRateLimit(kprobe.Selectors)
		has.sockTrack = has.sockTrack || selectors.HasSockTrack(&kprobe)
		has.override = has.override || selectors.HasOverride(kprobe.Selectors)
	}
	return has
}

func isArm() bool {
	return runtime.GOARCH == "arm64"
}

func createGenericKprobeSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
	valInfo []*kpValidateInfo,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var ids []idtable.EntryID
	var useMulti bool
	var selMaps *selectors.KernelSelectorMaps

	kprobes := spec.KProbes

	has := hasMapsSetup(spec)

	// use multi kprobe only if:
	// - it's not disabled by spec option
	// - it's not disabled by command line option
	// - there's support detected
	if !polInfo.specOpts.DisableKprobeMulti {
		useMulti = !option.Config.DisableKprobeMulti && bpf.HasKprobeMulti()

		// arm does not override on top of kprobe.multi
		if isArm() && (has.enforcer || has.override) {
			useMulti = false
		}
	}

	if useMulti {
		selMaps = &selectors.KernelSelectorMaps{}
	}

	in := addKprobeIn{
		useMulti:      useMulti,
		sensorPath:    name,
		policyID:      polInfo.policyID,
		policyName:    polInfo.name,
		customHandler: polInfo.customHandler,
		selMaps:       selMaps,
	}

	dups := make(map[string]int)

	for i := range kprobes {
		if valInfo[i].ignore {
			continue
		}
		syms := valInfo[i].calls
		syscall := valInfo[i].syscall
		// Syscall flag might be changed in list definition
		kprobes[i].Syscall = syscall

		for _, sym := range syms {
			// Make sure duplicate symbols got non zero instance value
			instance, ok := dups[sym]
			if ok {
				instance = instance + 1
			}
			dups[sym] = instance

			id, err := addKprobe(sym, instance, &kprobes[i], &in)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
	}

	var err error
	if useMulti {
		progs, maps, err = createMultiKprobeSensor(polInfo, ids, has)
	} else {
		progs, maps, err = createSingleKprobeSensor(polInfo, ids, has)
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
		DestroyHook: func() error {
			var errs error

			for _, id := range ids {
				gk, err := genericKprobeTableGet(id)
				if err != nil {
					errs = errors.Join(errs, err)
					continue
				}

				if err = selectors.CleanupKernelSelectorState(gk.loadArgs.selectors.entry); err != nil {
					errs = errors.Join(errs, err)
				}

				_, err = genericKprobeTable.RemoveEntry(id)
				if err != nil {
					errs = errors.Join(errs, err)
				}
			}
			return errs
		},
	}, nil
}

func initEventConfig() *api.EventConfig {
	return &api.EventConfig{
		ArgIndex: [api.EventConfigMaxArgs]int32{-1, -1, -1, -1, -1},
	}
}

// addKprobe will, amongst other things, create a generic kprobe entry and add
// it to the genericKprobeTable. The caller should make sure that this entry is
// properly removed on kprobe removal.
func addKprobe(funcName string, instance int, f *v1alpha1.KProbeSpec, in *addKprobeIn) (id idtable.EntryID, err error) {
	var argSigPrinters []argPrinter
	var argReturnPrinters []argPrinter
	var setRetprobe bool
	var argRetprobe *v1alpha1.KProbeArg
	var allBTFArgs [api.EventConfigMaxArgs][api.MaxBTFArgDepth]api.ConfigBTFArg

	errFn := func(err error) (idtable.EntryID, error) {
		return idtable.UninitializedEntryID, err
	}

	if f == nil {
		return errFn(errors.New("error adding kprobe, the kprobe spec is nil"))
	}

	eventConfig := initEventConfig()
	eventConfig.PolicyID = uint32(in.policyID)
	if len(f.ReturnArgAction) > 0 {
		if !config.EnableLargeProgs() {
			return errFn(errors.New("ReturnArgAction requires kernel >=5.3"))
		}
		eventConfig.ArgReturnAction = selectors.ActionTypeFromString(f.ReturnArgAction)
		if eventConfig.ArgReturnAction == selectors.ActionTypeInvalid {
			return errFn(fmt.Errorf("ReturnArgAction type '%s' unsupported", f.ReturnArgAction))
		}
	}

	if selectors.HasOverride(f.Selectors) {
		if err := validateOverride(f, funcName, in.useMulti); err != nil {
			return errFn(fmt.Errorf("override validation failed: %w", err))
		}
	}

	if in.useMulti && instance > 0 {
		return errFn(fmt.Errorf("error: can't have multiple instances of same symbol '%s' with kprobe_multi, use --disable-kprobe-multi option",
			funcName))
	}

	msgField, err := getPolicyMessage(f.Message)
	if errors.Is(err, ErrMsgSyntaxShort) || errors.Is(err, ErrMsgSyntaxEscape) {
		return errFn(fmt.Errorf("error: '%w'", err))
	} else if errors.Is(err, ErrMsgSyntaxLong) {
		logger.GetLogger().Warn(fmt.Sprintf("TracingPolicy 'message' field too long, truncated to %d characters", TpMaxMessageLen), "policy-name", in.policyName)
	}

	tagsField, err := GetPolicyTags(f.Tags)
	if err != nil {
		return errFn(fmt.Errorf("error: '%w'", err))
	}

	argRetprobe = nil // holds pointer to arg for return handler

	addArg := func(j int, a *v1alpha1.KProbeArg, data bool) error {
		// First try userspace types
		var argType int
		userArgType := gt.GenericUserTypeFromString(a.Type)

		if userArgType != gt.GenericInvalidType {
			// This is a userspace type, map it to kernel type
			argType = gt.GenericUserToKernelType(userArgType)
		} else {
			argType = gt.GenericTypeFromString(a.Type)
		}

		var (
			regArg api.ConfigRegArg
			ok     bool
		)

		if hasPtRegsSource(a) {
			regArg.Offset, regArg.Size, ok = asm.RegOffsetSize(a.Resolve)
			if !ok {
				return fmt.Errorf("error: Failed to retrieve register argument '%s'", a.Resolve)
			}
		} else if a.Resolve != "" && j < api.EventConfigMaxArgs {
			if !bpf.HasProgramLargeSize() {
				return errors.New("error: Resolve flag can't be used for your kernel version. Please update to version 5.4 or higher or disable Resolve flag")
			}
			lastBTFType, btfArg, err := resolveBTFArg(f.Call, a, false)
			if err != nil {
				return fmt.Errorf("error on hook %q for index %d : %w", f.Call, a.Index, err)
			}
			allBTFArgs[j] = btfArg
			argType = findTypeFromBTFType(a, lastBTFType)
		}

		if argType == gt.GenericInvalidType {
			return fmt.Errorf("Arg(%d) type '%s' unsupported", j, a.Type)
		}

		if a.MaxData {
			if argType != gt.GenericCharBuffer {
				logger.GetLogger().Warn("maxData flag is ignored (supported for char_buf type)")
			}
			if !config.EnableLargeProgs() {
				logger.GetLogger().Warn("maxData flag is ignored (supported from large programs)")
			}
		}
		argMValue, err := getMetaValue(a)
		if err != nil {
			return err
		}
		if argReturnCopy(argMValue) {
			argRetprobe = &f.Args[j]
		}
		if a.Index > 4 {
			return fmt.Errorf("error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index))
		}
		eventConfig.ArgType[j] = int32(argType)
		eventConfig.ArgMeta[j] = uint32(argMValue)
		eventConfig.ArgIndex[j] = int32(a.Index)
		eventConfig.RegArg[j] = regArg

		argP := argPrinter{
			index:    int(a.Index),
			ty:       argType,
			userType: userArgType,
			maxData:  a.MaxData,
			label:    a.Label,
			data:     data,
		}
		argSigPrinters = append(argSigPrinters, argP)

		pathArgWarning(a.Index, argType, f.Selectors)
		return nil
	}

	if len(f.Args)+len(f.Data) > api.EventConfigMaxArgs {
		return errFn(fmt.Errorf("too many arguments, max %d: args(%d) data(%d)", api.EventConfigMaxArgs, len(f.Args), len(f.Data)))
	}

	var j int

	// Parse Arguments
	for _, arg := range f.Args {
		if arg.Source != "" {
			return errFn(fmt.Errorf("standard argument is not allowed to have source configured, current value: '%s'", arg.Source))
		}
		if err := addArg(j, &arg, false); err != nil {
			return errFn(err)
		}
		j = j + 1
	}

	// Parse Data
	for _, data := range f.Data {
		if !hasCurrentTaskSource(&data) && !hasPtRegsSource(&data) {
			return errFn(fmt.Errorf("data argument has wrong source '%s'", data.Source))
		}
		if data.Resolve == "" {
			return errFn(errors.New("data argument missing 'resolve' setup"))
		}
		if err := addArg(j, &data, true); err != nil {
			return errFn(err)
		}
		j = j + 1
	}

	eventConfig.BTFArg = allBTFArgs

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
			return errFn(errors.New("ReturnArg not specified with Return=true"))
		}
		argType := gt.GenericTypeFromString(f.ReturnArg.Type)
		if argType == gt.GenericInvalidType {
			if f.ReturnArg.Type == "" {
				return errFn(errors.New("ReturnArg not specified with Return=true"))
			}
			return errFn(fmt.Errorf("ReturnArg type '%s' unsupported", f.ReturnArg.Type))
		}
		eventConfig.ArgReturn = int32(argType)
		argP := argPrinter{index: api.ReturnArgIndex, ty: argType}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		eventConfig.ArgReturn = int32(gt.GenericUnsetType)
	}

	if argRetprobe != nil {
		setRetprobe = true

		argType := gt.GenericTypeFromString(argRetprobe.Type)
		val := int32(argType)
		if argType == gt.GenericInt32ArrType {
			val |= int32(argRetprobe.Size << 8)
		}
		eventConfig.ArgReturnCopy = val

		argP := argPrinter{index: int(argRetprobe.Index), ty: argType, label: argRetprobe.Label}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		eventConfig.ArgReturnCopy = int32(gt.GenericUnsetType)
	}

	// Write attributes into BTF ptr for use with load
	if !setRetprobe {
		setRetprobe = f.Return
	}

	if f.Syscall {
		eventConfig.Syscall = 1
	} else {
		eventConfig.Syscall = 0
	}

	// create a new entry on the table, and pass its id to BPF-side
	// so that we can do the matching at event-generation time
	kprobeEntry := genericKprobe{
		loadArgs: kprobeLoadArgs{
			retprobe: setRetprobe,
			syscall:  f.Syscall,
			config:   eventConfig,
		},
		argSigPrinters:    argSigPrinters,
		argReturnPrinters: argReturnPrinters,
		funcName:          funcName,
		instance:          instance,
		pendingEvents:     nil,
		tableId:           idtable.UninitializedEntryID,
		policyName:        in.policyName,
		hasOverride:       selectors.HasOverride(f.Selectors),
		customHandler:     in.customHandler,
		message:           msgField,
		tags:              tagsField,
		hasStackTrace:     selectors.HasStackTrace(f.Selectors),
	}

	// Parse Filters into kernel filter logic
	kprobeEntry.loadArgs.selectors.entry, err = selectors.InitKernelSelectorState(&selectors.KernelSelectorArgs{
		Selectors:      f.Selectors,
		Args:           f.Args,
		Data:           f.Data,
		ActionArgTable: &kprobeEntry.actionArgs,
		Maps:           in.selMaps,
	})
	if err != nil {
		return errFn(err)
	}

	if f.Return {
		kprobeEntry.loadArgs.selectors.retrn, err = selectors.InitKernelReturnSelectorState(f.Selectors, f.ReturnArg,
			&kprobeEntry.actionArgs, nil, in.selMaps)
		if err != nil {
			return errFn(err)
		}
	}

	kprobeEntry.pendingEvents, err = lru.New[pendingEventKey, pendingEvent[*tracing.MsgGenericKprobeUnix]](option.Config.RetprobesCacheSize)
	if err != nil {
		return errFn(err)
	}

	genericKprobeTable.AddEntry(&kprobeEntry)
	eventConfig.FuncId = uint32(kprobeEntry.tableId.ID)

	logger.GetLogger().
		Info("Added kprobe", "return", setRetprobe, "function", kprobeEntry.funcName, "override", kprobeEntry.hasOverride)

	return kprobeEntry.tableId, nil
}

func createKprobeSensorFromEntry(polInfo *policyInfo, kprobeEntry *genericKprobe,
	progs []*program.Program, maps []*program.Map, has hasMaps) ([]*program.Program, []*program.Map) {

	loadProgName, loadProgRetName := config.GenericKprobeObjs(false)
	isSecurityFunc := strings.HasPrefix(kprobeEntry.funcName, "security_")

	pinProg := kprobeEntry.funcName
	if kprobeEntry.instance != 0 {
		pinProg = fmt.Sprintf("%s:%d", kprobeEntry.funcName, kprobeEntry.instance)
	}

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		kprobeEntry.funcName,
		"kprobe/generic_kprobe",
		pinProg,
		"generic_kprobe").
		SetLoaderData(kprobeEntry.tableId).
		SetPolicy(kprobeEntry.policyName)
	load.Override = kprobeEntry.hasOverride
	if load.Override {
		load.OverrideFmodRet = isSecurityFunc && bpf.HasModifyReturn()
	}
	progs = append(progs, load)

	fdinstall := program.MapBuilderSensor("fdinstall_map", load)
	if has.fdInstall {
		fdinstall.SetMaxEntries(fdInstallMapMaxEntries)
	}
	maps = append(maps, fdinstall)

	configMap := program.MapBuilderProgram("config_map", load)
	maps = append(maps, configMap)

	tailCalls := program.MapBuilderProgram("kprobe_calls", load)
	maps = append(maps, tailCalls)

	filterMap := program.MapBuilderProgram("filter_map", load)
	maps = append(maps, filterMap)

	maps = append(maps, filterMaps(load, kprobeEntry)...)

	retProbe := program.MapBuilderSensor("retprobe_map", load)
	maps = append(maps, retProbe)

	callHeap := program.MapBuilderSensor("process_call_heap", load)
	maps = append(maps, callHeap)

	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, selMatchBinariesMap)

	matchBinariesPaths := program.MapBuilderProgram("tg_mb_paths", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		matchBinariesPaths.SetInnerMaxEntries(kprobeEntry.loadArgs.selectors.entry.MatchBinariesPathsMaxEntries())
	}
	maps = append(maps, matchBinariesPaths)

	// loading the stack trace map in any case so that it does not end up as an
	// anonymous map (as it's always used by the BPF prog) and is clearly linked
	// to tetragon
	stackTraceMap := program.MapBuilderProgram("stack_trace_map", load)
	if has.stackTrace {
		// to reduce memory footprint however, the stack map is created with a
		// max entry of 1, we need to expand that at loading.
		stackTraceMap.SetMaxEntries(stackTraceMapMaxEntries)
	}
	maps = append(maps, stackTraceMap)
	kprobeEntry.data.stackTraceMap = stackTraceMap

	if config.EnableLargeProgs() {
		socktrack := program.MapBuilderSensor("socktrack_map", load)
		if has.sockTrack {
			socktrack.SetMaxEntries(socktrackMapMaxEntries)
		}
		maps = append(maps, socktrack)
	}

	if config.EnableLargeProgs() {
		ratelimitMap := program.MapBuilderSensor("ratelimit_map", load)
		if has.rateLimit {
			// similarly as for stacktrace, we expand the max size only if
			// needed to reduce the memory footprint when unused
			ratelimitMap.SetMaxEntries(ratelimitMapMaxEntries)
		}
		maps = append(maps, ratelimitMap)
	}

	if has.enforcer {
		maps = append(maps, enforcerMapsUser(load)...)
	}

	if option.Config.EnableCgTrackerID {
		maps = append(maps, program.MapUser(cgtracker.MapName, load))
	}

	overrideTasksMap := program.MapBuilderProgram("override_tasks", load)
	if has.override {
		overrideTasksMap.SetMaxEntries(overrideMapMaxEntries)
	}
	maps = append(maps, overrideTasksMap)

	maps = append(maps, polInfo.policyConfMap(load), polInfo.policyStatsMap(load))

	if kprobeEntry.loadArgs.retprobe {
		pinRetProg := sensors.PathJoin(kprobeEntry.funcName + "_return")
		if kprobeEntry.instance != 0 {
			pinRetProg = sensors.PathJoin(fmt.Sprintf("%s_return:%d", kprobeEntry.funcName, kprobeEntry.instance))
		}
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			kprobeEntry.funcName,
			"kprobe/generic_retkprobe",
			pinRetProg,
			"generic_kprobe").
			SetRetProbe(true).
			SetLoaderData(kprobeEntry.tableId).
			SetPolicy(kprobeEntry.policyName)
		progs = append(progs, loadret)

		retProbe := program.MapBuilderSensor("retprobe_map", loadret)
		maps = append(maps, retProbe)

		retConfigMap := program.MapBuilderProgram("config_map", loadret)
		maps = append(maps, retConfigMap)

		tailCalls := program.MapBuilderProgram("retkprobe_calls", loadret)
		maps = append(maps, tailCalls)

		filterMap := program.MapBuilderProgram("filter_map", loadret)
		maps = append(maps, filterMap)

		maps = append(maps, filterMaps(loadret, kprobeEntry)...)

		// add maps with non-default paths (pins) to the retprobe
		callHeap := program.MapBuilderSensor("process_call_heap", loadret)
		maps = append(maps, callHeap)

		fdinstall := program.MapBuilderSensor("fdinstall_map", loadret)
		if has.fdInstall {
			fdinstall.SetMaxEntries(fdInstallMapMaxEntries)
		}
		maps = append(maps, fdinstall)

		if config.EnableLargeProgs() {
			socktrack := program.MapBuilderSensor("socktrack_map", loadret)
			if has.sockTrack {
				socktrack.SetMaxEntries(socktrackMapMaxEntries)
			}
			maps = append(maps, socktrack)
		}
	}

	logger.GetLogger().Info(fmt.Sprintf("Added generic kprobe sensor: %s -> %s", load.Name, load.Attach),
		"override", kprobeEntry.hasOverride)
	return progs, maps
}

func createSingleKprobeSensor(polInfo *policyInfo, ids []idtable.EntryID, has hasMaps) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	for _, id := range ids {
		gk, err := genericKprobeTableGet(id)
		if err != nil {
			return nil, nil, err
		}
		gk.data = &genericKprobeData{}

		// setup per kprobe map config
		has.stackTrace = gk.hasStackTrace
		has.override = gk.hasOverride

		progs, maps = createKprobeSensorFromEntry(polInfo, gk, progs, maps, has)
	}

	return progs, maps, nil
}

func getMapLoad(load *program.Program, kprobeEntry *genericKprobe, index uint32) []*program.MapLoad {
	state := getProgramSelector(load, kprobeEntry)
	if state == nil {
		return []*program.MapLoad{}
	}
	return selectorsMaploads(state, index)
}

func loadSingleKprobeSensor(id idtable.EntryID, bpfDir string, load *program.Program, maps []*program.Map, verbose int) error {
	gk, err := genericKprobeTableGet(id)
	if err != nil {
		return err
	}

	load.MapLoad = append(load.MapLoad, getMapLoad(load, gk, 0)...)

	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, gk.loadArgs.config)
	config := &program.MapLoad{
		Name: "config_map",
		Load: func(m *ebpf.Map, _ string) error {
			return m.Update(uint32(0), configData.Bytes()[:], ebpf.UpdateAny)
		},
	}
	load.MapLoad = append(load.MapLoad, config)

	if err := program.LoadKprobeProgram(bpfDir, load, maps, verbose); err == nil {
		logger.GetLogger().Info(fmt.Sprintf("Loaded generic kprobe program: %s -> %s", load.Name, load.Attach))
	} else {
		return err
	}

	return err
}

func loadMultiKprobeSensor(ids []idtable.EntryID, bpfDir string, load *program.Program, maps []*program.Map, verbose int) error {
	binBuf := make([]bytes.Buffer, len(ids))

	data := &program.MultiKprobeAttachData{}

	for index, id := range ids {
		gk, err := genericKprobeTableGet(id)
		if err != nil {
			return err
		}

		load.MapLoad = append(load.MapLoad, getMapLoad(load, gk, uint32(index))...)

		binary.Write(&binBuf[index], binary.LittleEndian, gk.loadArgs.config)
		config := &program.MapLoad{
			Name: "config_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(uint32(index), binBuf[index].Bytes()[:], ebpf.UpdateAny)
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

	if err := program.LoadMultiKprobeProgram(bpfDir, load, maps, verbose); err == nil {
		logger.GetLogger().Info(fmt.Sprintf("Loaded generic kprobe sensor: %s -> %s", load.Name, load.Attach))
	} else {
		return err
	}

	return nil
}

func loadGenericKprobeSensor(bpfDir string, load *program.Program, maps []*program.Map, verbose int) error {
	if id, ok := load.LoaderData.(idtable.EntryID); ok {
		return loadSingleKprobeSensor(id, bpfDir, load, maps, verbose)
	}
	if ids, ok := load.LoaderData.([]idtable.EntryID); ok {
		return loadMultiKprobeSensor(ids, bpfDir, load, maps, verbose)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}

func getUrl(url string) {
	// We fire and forget URLs, and we don't care if they hit or not.
	http.Get(url)
}

func dnsLookup(fqdn string) {
	// We fire and forget DNS lookups, and we don't care if they hit or not.
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
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
		logger.GetLogger().Warn("Failed to read process call msg", logfields.Error, err)
		return nil, errors.New("failed to read process call msg")
	}

	gk, err := genericKprobeTableGet(idtable.EntryID{ID: int(m.FuncId)})
	if err != nil {
		logger.GetLogger().Warn(fmt.Sprintf("Failed to match id:%d", m.FuncId), logfields.Error, err)
		return nil, errors.New("failed to match id")
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
			logger.GetLogger().Warn(fmt.Sprintf("Failed to find argument for id:%d", m.ActionArgId), logfields.Error, err)
			return nil, errors.New("failed to find argument for id")
		}
		actionArg := actionArgEntry.(*selectors.ActionArgEntry).GetArg()
		switch m.ActionId {
		case selectors.ActionTypeGetUrl:
			logger.Trace(logger.GetLogger(), "Get URL Action", "URL", actionArg)
			getUrl(actionArg)
		case selectors.ActionTypeDnsLookup:
			logger.Trace(logger.GetLogger(), "DNS lookup", "FQDN", actionArg)
			dnsLookup(actionArg)
		}
	}

	unix := &tracing.MsgGenericKprobeUnix{}
	unix.Msg = m
	unix.FuncName = gk.funcName
	unix.PolicyName = gk.policyName
	unix.Message = gk.message
	unix.Tags = gk.tags

	returnEvent := m.Common.Flags&processapi.MSG_COMMON_FLAG_RETURN != 0

	var ktimeEnter uint64
	var printers []argPrinter
	if returnEvent {
		// if this a return event, also read the ktime of the enter event
		err := binary.Read(r, binary.LittleEndian, &ktimeEnter)
		if err != nil {
			return nil, errors.New("failed to read ktimeEnter")
		}
		printers = gk.argReturnPrinters
	} else {
		ktimeEnter = m.Common.Ktime
		printers = gk.argSigPrinters
	}

	if m.Common.Flags&(processapi.MSG_COMMON_FLAG_KERNEL_STACKTRACE|processapi.MSG_COMMON_FLAG_USER_STACKTRACE) != 0 {
		if m.KernelStackID < 0 {
			logger.GetLogger().Warn(fmt.Sprintf("failed to retrieve kernel stacktrace: id equal to errno %d", m.KernelStackID))
		}
		if m.UserStackID < 0 {
			logger.GetLogger().Debug(fmt.Sprintf("failed to retrieve user stacktrace: id equal to errno %d", m.UserStackID))
		}
		if gk.data.stackTraceMap.MapHandle == nil {
			logger.GetLogger().Warn("failed to load the stacktrace map", logfields.Error, err)
		}
		if m.KernelStackID > 0 || m.UserStackID > 0 {
			// remove the error part
			if m.KernelStackID > 0 {
				id := uint32(m.KernelStackID)
				err = gk.data.stackTraceMap.MapHandle.Lookup(id, &unix.KernelStackTrace)
				if err != nil {
					logger.GetLogger().Warn("failed to lookup the stacktrace map", logfields.Error, err)
				}
			}
			if m.UserStackID > 0 {
				id := uint32(m.UserStackID)
				err = gk.data.stackTraceMap.MapHandle.Lookup(id, &unix.UserStackTrace)
				if err != nil {
					logger.GetLogger().Warn("failed to lookup the stacktrace map", logfields.Error, err)
				}
			}
		}
	}

	// Get argument objects for specific printers/types
	for _, a := range printers {
		arg := getArg(r, a)
		// nop or unknown type (already logged)
		if arg == nil {
			continue
		}
		if a.data {
			unix.Data = append(unix.Data, arg)
		} else {
			unix.Args = append(unix.Args, arg)
		}
	}

	// Cache return value on merge and run return filters below before
	// passing up to notify hooks.

	// there are two events for this probe (entry and return)
	if gk.loadArgs.retprobe {
		var (
			other  *tracing.MsgGenericKprobeUnix
			merged bool
		)
		merged, unix, other = retprobeMergeEvents[*tracing.MsgGenericKprobeUnix](
			unix,
			gk.pendingEvents,
			returnEvent,
			m.RetProbeId,
			ktimeEnter,
			reportKprobeMergeError)
		if unix != nil {
			kprobemetrics.MergeOkTotalInc()
			unix.ReturnAction = other.Msg.ActionId
		} else if !merged {
			kprobemetrics.MergePushedInc()
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

	return []observer.Event{unix}, err
}

func reportKprobeMergeError(curr pendingEvent[*tracing.MsgGenericKprobeUnix], prev pendingEvent[*tracing.MsgGenericKprobeUnix]) {
	currFn := "UNKNOWN"
	if curr.ev != nil {
		currFn = curr.ev.FuncName
	}
	currType := kprobemetrics.MergeErrorTypeEnter
	if curr.returnEvent {
		currType = kprobemetrics.MergeErrorTypeExit
	}

	prevFn := "UNKNOWN"
	if prev.ev != nil {
		prevFn = prev.ev.FuncName
	}
	prevType := kprobemetrics.MergeErrorTypeEnter
	if prev.returnEvent {
		prevType = kprobemetrics.MergeErrorTypeExit
	}

	kprobemetrics.MergeErrorsInc(currFn, prevFn, currType, prevType)
	logger.GetLogger().Debug("failed to merge events",
		"currFn", currFn,
		"currType", currType.String(),
		"prevFn", prevFn,
		"prevType", prevType.String())
}

type reportMergeErorrFn[T evArgsRetriever] func(curr pendingEvent[T], prev pendingEvent[T])

type evArgsRetriever interface {
	GetArgs() *[]api.MsgGenericKprobeArg
	// This constraint allows us to return nil from methods
	*tracing.MsgGenericKprobeUnix | *tracing.MsgGenericUprobeUnix
}

// retprobeMerge merges the two events: the one from the entry probe with the one from the return probe
func retprobeMerge[T evArgsRetriever](prev pendingEvent[T], curr pendingEvent[T],
	onMergeError reportMergeErorrFn[T]) (T, T) {
	var retEv, enterEv T

	if prev.returnEvent && !curr.returnEvent {
		retEv = prev.ev
		enterEv = curr.ev
	} else if !prev.returnEvent && curr.returnEvent {
		retEv = curr.ev
		enterEv = prev.ev
	} else {
		onMergeError(curr, prev)
		return nil, nil
	}

	retArgs := retEv.GetArgs()
	enterArgs := enterEv.GetArgs()
	for _, retArg := range *retArgs {
		index := retArg.GetIndex()
		if uint64(len(*enterArgs)) > index {
			(*enterArgs)[index] = retArg
		} else {
			*enterArgs = append(*enterArgs, retArg)
		}
	}
	return enterEv, retEv
}

func retprobeMergeEvents[T evArgsRetriever](unix T, pendingEvents *lru.Cache[pendingEventKey, pendingEvent[T]],
	returnEvent bool, retprobeId, ktimeEnter uint64, onMergeError reportMergeErorrFn[T]) (bool, T, T) {
	// if an event exist already, try to merge them. Otherwise, add
	// the one we have in the map.
	curr := pendingEvent[T]{ev: unix, returnEvent: returnEvent}
	key := pendingEventKey{eventId: retprobeId, ktimeEnter: ktimeEnter}

	if prev, exists := pendingEvents.Get(key); exists {
		pendingEvents.Remove(key)
		enter, exit := retprobeMerge[T](prev, curr, onMergeError)
		return true, enter, exit
	}
	pendingEvents.Add(key, curr)
	return false, nil, nil
}

func (k *observerKprobeSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadGenericKprobeSensor(args.BPFDir, args.Load, args.Maps, args.Verbose)
}
