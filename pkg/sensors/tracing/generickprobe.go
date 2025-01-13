// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

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
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/cgtracker"
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
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
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

	// The following values could be fine tuned if either those feature use too
	// much kernel memory when enabled.
	stackTraceMapMaxEntries = 32768
	ratelimitMapMaxEntries  = 32768
	fdInstallMapMaxEntries  = 32000
	enforcerMapMaxEntries   = 32768
	overrideMapMaxEntries   = 32768
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
	pendingEvents *lru.Cache[pendingEventKey, pendingEvent]

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

	// is there ratelimit defined in the kprobe
	hasRatelimit bool

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

	for string_map_index := 0; string_map_index < numSubMaps; string_map_index++ {
		stringFilterMap[string_map_index] = program.MapBuilderProgram(fmt.Sprintf("string_maps_%d", string_map_index), load)
		if state != nil && !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := state.StringMapsMaxEntries(string_map_index)
			stringFilterMap[string_map_index].SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, stringFilterMap[string_map_index])
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

func createMultiKprobeSensor(policyName string, multiIDs []idtable.EntryID, has hasMaps) ([]*program.Program, []*program.Map, error) {
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
		has.rateLimit = has.rateLimit || gk.hasRatelimit
		has.override = has.override || gk.hasOverride
	}

	loadProgName := "bpf_multi_kprobe_v53.o"
	loadProgRetName := "bpf_multi_retkprobe_v53.o"
	if kernels.EnableV61Progs() {
		loadProgName = "bpf_multi_kprobe_v61.o"
		loadProgRetName = "bpf_multi_retkprobe_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		loadProgName = "bpf_multi_kprobe_v511.o"
		loadProgRetName = "bpf_multi_retkprobe_v511.o"
	}

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("kprobe_multi (%d functions)", len(multiIDs)),
		"kprobe.multi/generic_kprobe",
		"multi_kprobe",
		"generic_kprobe").
		SetLoaderData(multiIDs).
		SetPolicy(policyName)
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

	if kernels.EnableLargeProgs() {
		socktrack := program.MapBuilderSensor("socktrack_map", load)
		maps = append(maps, socktrack)
	}

	if kernels.EnableLargeProgs() {
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

	maps = append(maps, program.MapUser(base.ExecveMap.Name, load))

	if len(multiRetIDs) != 0 {
		loadret := program.Builder(
			path.Join(option.Config.HubbleLib, loadProgRetName),
			fmt.Sprintf("%d retkprobes", len(multiIDs)),
			"kprobe.multi/generic_retkprobe",
			"multi_retkprobe",
			"generic_kprobe").
			SetRetProbe(true).
			SetLoaderData(multiRetIDs).
			SetPolicy(policyName)
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
		maps = append(maps, socktrack)

		tailCalls := program.MapBuilderSensor("retkprobe_calls", loadret)
		maps = append(maps, tailCalls)

		retConfigMap.SetMaxEntries(len(multiRetIDs))
		retFilterMap.SetMaxEntries(len(multiRetIDs))

		maps = append(maps, program.MapUser(base.ExecveMap.Name, loadret))
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

// preValidateKprobes pre-validates the semantics and BTF information of a Kprobe spec
//
// Pre validate the kprobe semantics and BTF information in order to separate
// the kprobe errors from BPF related ones.
func preValidateKprobes(name string, kprobes []v1alpha1.KProbeSpec, lists []v1alpha1.ListSpec) error {
	btfobj, err := btf.NewBTF()
	if err != nil {
		return err
	}

	// validate lists first
	err = preValidateLists(lists)
	if err != nil {
		return err
	}

	for i := range kprobes {
		f := &kprobes[i]

		var calls []string

		// the f.Call is either defined as list:NAME
		// or specifies directly the function
		if isL, list := isList(f.Call, lists); isL {
			if list == nil {
				return fmt.Errorf("Error list '%s' not found", f.Call)
			}
			var err error
			calls, err = getListSymbols(list)
			if err != nil {
				return fmt.Errorf("failed to get symbols from list '%s': %w", f.Call, err)
			}
		} else {
			if f.Syscall {
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
			calls = []string{f.Call}
		}

		for sid, selector := range f.Selectors {
			for mid, matchAction := range selector.MatchActions {
				if (matchAction.KernelStackTrace || matchAction.UserStackTrace) && matchAction.Action != "Post" {
					return fmt.Errorf("kernelStackTrace or userStackTrace can only be used along Post action: got (kernelStackTrace/userStackTrace) enabled in kprobes[%d].selectors[%d].matchActions[%d] with action '%s'", i, sid, mid, matchAction.Action)
				}
			}
		}

		if selectors.HasOverride(f) {
			if !bpf.HasOverrideHelper() {
				return fmt.Errorf("Error override action not supported, bpf_override_return helper not available")
			}
			if !f.Syscall {
				for idx := range calls {
					if !strings.HasPrefix(calls[idx], "security_") {
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
			if err := validateKprobeType(arg.Type); err != nil {
				return fmt.Errorf("spec.kprobes[%d].args[%d].type: %w", i, idxArg, err)
			}
		}
	}

	return nil
}

type addKprobeIn struct {
	useMulti      bool
	sensorPath    string
	policyName    string
	policyID      policyfilter.PolicyID
	customHandler eventhandler.Handler
	selMaps       *selectors.KernelSelectorMaps
}

func getKprobeSymbols(symbol string, syscall bool, lists []v1alpha1.ListSpec) ([]string, bool, error) {
	if isL, list := isList(symbol, lists); isL {
		if list == nil {
			return nil, false, fmt.Errorf("list '%s' not found", symbol)
		}
		symbols, err := getListSymbols(list)
		if err != nil {
			return nil, true, fmt.Errorf("failed to get kprobe symbols from syscall list: %w", err)
		}
		return symbols, isSyscallListType(list.Type), nil
	}
	return []string{symbol}, syscall, nil
}

type hasMaps struct {
	stackTrace bool
	rateLimit  bool
	fdInstall  bool
	enforcer   bool
	override   bool
}

// hasMapsSetup setups the has maps for the per policy maps. The per kprobe maps
// are setup later in createSingleKprobeSensor or createMultiKprobeSensor.
func hasMapsSetup(spec *v1alpha1.TracingPolicySpec) hasMaps {
	has := hasMaps{}
	for _, kprobe := range spec.KProbes {
		has.fdInstall = has.fdInstall || selectorsHaveFDInstall(kprobe.Selectors)
		has.enforcer = has.enforcer || len(spec.Enforcers) != 0

		// check for early break
		if has.fdInstall && has.enforcer {
			break
		}
	}
	return has
}

func createGenericKprobeSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	policyID policyfilter.PolicyID,
	policyName string,
	namespace string,
	customHandler eventhandler.Handler,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var ids []idtable.EntryID
	var useMulti bool
	var selMaps *selectors.KernelSelectorMaps

	kprobes := spec.KProbes
	lists := spec.Lists

	specOpts, err := getSpecOptions(spec.Options)
	if err != nil {
		return nil, fmt.Errorf("failed to get spec options: %s", err)
	}

	// use multi kprobe only if:
	// - it's not disabled by spec option
	// - it's not disabled by command line option
	// - there's support detected
	if !specOpts.DisableKprobeMulti {
		useMulti = !option.Config.DisableKprobeMulti && bpf.HasKprobeMulti()
	}

	if useMulti {
		selMaps = &selectors.KernelSelectorMaps{}
	}

	in := addKprobeIn{
		useMulti:      useMulti,
		sensorPath:    name,
		policyID:      policyID,
		policyName:    policyName,
		customHandler: customHandler,
		selMaps:       selMaps,
	}

	has := hasMapsSetup(spec)
	dups := make(map[string]int)

	for i := range kprobes {
		syms, syscall, err := getKprobeSymbols(kprobes[i].Call, kprobes[i].Syscall, lists)
		if err != nil {
			return nil, err
		}

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

	if useMulti {
		progs, maps, err = createMultiKprobeSensor(in.policyName, ids, has)
	} else {
		progs, maps, err = createSingleKprobeSensor(ids, has)
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
		DestroyHook: func() error {
			var errs error
			for _, id := range ids {
				_, err := genericKprobeTable.RemoveEntry(id)
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
func addKprobe(funcName string, instance int, f *v1alpha1.KProbeSpec, in *addKprobeIn) (id idtable.EntryID, err error) {
	var argSigPrinters []argPrinter
	var argReturnPrinters []argPrinter
	var setRetprobe bool
	var argRetprobe *v1alpha1.KProbeArg
	var argsBTFSet [api.MaxArgsSupported]bool

	errFn := func(err error) (idtable.EntryID, error) {
		return idtable.UninitializedEntryID, err
	}

	if f == nil {
		return errFn(errors.New("error adding kprobe, the kprobe spec is nil"))
	}

	config := &api.EventConfig{}
	config.PolicyID = uint32(in.policyID)
	if len(f.ReturnArgAction) > 0 {
		if !kernels.EnableLargeProgs() {
			return errFn(fmt.Errorf("ReturnArgAction requires kernel >=5.3"))
		}
		config.ArgReturnAction = selectors.ActionTypeFromString(f.ReturnArgAction)
		if config.ArgReturnAction == selectors.ActionTypeInvalid {
			return errFn(fmt.Errorf("ReturnArgAction type '%s' unsupported", f.ReturnArgAction))
		}
	}

	isSecurityFunc := strings.HasPrefix(funcName, "security_")

	if selectors.HasOverride(f) {
		if isSecurityFunc && in.useMulti {
			return errFn(fmt.Errorf("Error: can't override '%s' function with kprobe_multi, use --disable-kprobe-multi option",
				funcName))
		}
		if isSecurityFunc && !bpf.HasModifyReturn() {
			return errFn(fmt.Errorf("Error: can't override '%s' function without fmodret support",
				funcName))
		}
	}

	if in.useMulti && instance > 0 {
		return errFn(fmt.Errorf("Error: can't have multiple instances of same symbol '%s' with kprobe_multi, use --disable-kprobe-multi option",
			funcName))
	}

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

	argRetprobe = nil // holds pointer to arg for return handler

	// Parse Arguments
	for j, a := range f.Args {
		// First try userspace types
		var argType int
		userArgType := gt.GenericUserTypeFromString(a.Type)

		if userArgType != gt.GenericInvalidType {
			// This is a userspace type, map it to kernel type
			argType = gt.GenericUserToKernelType(userArgType)
		} else {
			argType = gt.GenericTypeFromString(a.Type)
		}

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
		if argReturnCopy(argMValue) {
			argRetprobe = &f.Args[j]
		}
		if a.Index > 4 {
			return errFn(fmt.Errorf("Error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index)))
		}
		config.Arg[a.Index] = int32(argType)
		config.ArgM[a.Index] = uint32(argMValue)

		argsBTFSet[a.Index] = true
		argP := argPrinter{index: j, ty: argType, userType: userArgType, maxData: a.MaxData, label: a.Label}
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
			return errFn(fmt.Errorf("ReturnArg not specified with Return=true"))
		}
		argType := gt.GenericTypeFromString(f.ReturnArg.Type)
		if argType == gt.GenericInvalidType {
			if f.ReturnArg.Type == "" {
				return errFn(fmt.Errorf("ReturnArg not specified with Return=true"))
			}
			return errFn(fmt.Errorf("ReturnArg type '%s' unsupported", f.ReturnArg.Type))
		}
		config.ArgReturn = int32(argType)
		argsBTFSet[api.ReturnArgIndex] = true
		argP := argPrinter{index: api.ReturnArgIndex, ty: argType}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		config.ArgReturn = int32(0)
	}

	if argRetprobe != nil {
		argsBTFSet[api.ReturnArgIndex] = true
		setRetprobe = true

		argType := gt.GenericTypeFromString(argRetprobe.Type)
		config.ArgReturnCopy = int32(argType)

		argP := argPrinter{index: int(argRetprobe.Index), ty: argType, label: argRetprobe.Label}
		argReturnPrinters = append(argReturnPrinters, argP)
	} else {
		config.ArgReturnCopy = int32(0)
	}

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

	// Write attributes into BTF ptr for use with load
	if !setRetprobe {
		setRetprobe = f.Return
	}

	if f.Syscall {
		config.Syscall = 1
	} else {
		config.Syscall = 0
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
		funcName:          funcName,
		instance:          instance,
		pendingEvents:     nil,
		tableId:           idtable.UninitializedEntryID,
		policyName:        in.policyName,
		hasOverride:       selectors.HasOverride(f),
		customHandler:     in.customHandler,
		message:           msgField,
		tags:              tagsField,
		hasStackTrace:     selectorsHaveStackTrace(f.Selectors),
		hasRatelimit:      selectorsHaveRateLimit(f.Selectors),
	}

	// Parse Filters into kernel filter logic
	kprobeEntry.loadArgs.selectors.entry, err = selectors.InitKernelSelectorState(f.Selectors, f.Args, &kprobeEntry.actionArgs, nil, in.selMaps)
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

	kprobeEntry.pendingEvents, err = lru.New[pendingEventKey, pendingEvent](4096)
	if err != nil {
		return errFn(err)
	}

	genericKprobeTable.AddEntry(&kprobeEntry)
	config.FuncId = uint32(kprobeEntry.tableId.ID)

	logger.GetLogger().
		WithField("return", setRetprobe).
		WithField("function", kprobeEntry.funcName).
		WithField("override", kprobeEntry.hasOverride).
		Infof("Added kprobe")

	return kprobeEntry.tableId, nil
}

func createKprobeSensorFromEntry(kprobeEntry *genericKprobe,
	progs []*program.Program, maps []*program.Map, has hasMaps) ([]*program.Program, []*program.Map) {

	loadProgName, loadProgRetName := kernels.GenericKprobeObjs()
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

	if kernels.EnableLargeProgs() {
		socktrack := program.MapBuilderSensor("socktrack_map", load)
		maps = append(maps, socktrack)
	}

	if kernels.EnableLargeProgs() {
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

	maps = append(maps, program.MapUser(base.ExecveMap.Name, load))

	if kprobeEntry.loadArgs.retprobe {
		pinRetProg := sensors.PathJoin(fmt.Sprintf("%s_return", kprobeEntry.funcName))
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

		if kernels.EnableLargeProgs() {
			socktrack := program.MapBuilderSensor("socktrack_map", loadret)
			maps = append(maps, socktrack)
		}
		maps = append(maps, program.MapUser(base.ExecveMap.Name, loadret))
	}

	logger.GetLogger().WithField("override", kprobeEntry.hasOverride).
		Infof("Added generic kprobe sensor: %s -> %s", load.Name, load.Attach)
	return progs, maps
}

func createSingleKprobeSensor(ids []idtable.EntryID, has hasMaps) ([]*program.Program, []*program.Map, error) {
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
		has.rateLimit = gk.hasRatelimit
		has.override = gk.hasOverride

		progs, maps = createKprobeSensorFromEntry(gk, progs, maps, has)
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

func loadSingleKprobeSensor(id idtable.EntryID, bpfDir string, load *program.Program, verbose int) error {
	gk, err := genericKprobeTableGet(id)
	if err != nil {
		return err
	}

	load.MapLoad = append(load.MapLoad, getMapLoad(load, gk, 0)...)

	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, gk.loadArgs.config)
	config := &program.MapLoad{
		Index: 0,
		Name:  "config_map",
		Load: func(m *ebpf.Map, _ string, index uint32) error {
			return m.Update(index, configData.Bytes()[:], ebpf.UpdateAny)
		},
	}
	load.MapLoad = append(load.MapLoad, config)

	if err := program.LoadKprobeProgram(bpfDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe program: %s -> %s", load.Name, load.Attach)
	} else {
		return err
	}

	return err
}

func loadMultiKprobeSensor(ids []idtable.EntryID, bpfDir string, load *program.Program, verbose int) error {
	bin_buf := make([]bytes.Buffer, len(ids))

	data := &program.MultiKprobeAttachData{}

	for index, id := range ids {
		gk, err := genericKprobeTableGet(id)
		if err != nil {
			return err
		}

		load.MapLoad = append(load.MapLoad, getMapLoad(load, gk, uint32(index))...)

		binary.Write(&bin_buf[index], binary.LittleEndian, gk.loadArgs.config)
		config := &program.MapLoad{
			Index: uint32(index),
			Name:  "config_map",
			Load: func(m *ebpf.Map, _ string, index uint32) error {
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

	if err := program.LoadMultiKprobeProgram(bpfDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe sensor: %s -> %s", load.Name, load.Attach)
	} else {
		return err
	}

	return nil
}

func loadGenericKprobeSensor(bpfDir string, load *program.Program, verbose int) error {
	if id, ok := load.LoaderData.(idtable.EntryID); ok {
		return loadSingleKprobeSensor(id, bpfDir, load, verbose)
	}
	if ids, ok := load.LoaderData.([]idtable.EntryID); ok {
		return loadMultiKprobeSensor(ids, bpfDir, load, verbose)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}

var errParseStringSize = errors.New("error parsing string size from binary")

// this is from bpf/process/types/basic.h 'MAX_STRING'
const maxStringSize = 4096
const maxStringSizeSmall = 510
const maxStringSizeTiny = 144

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
			return nil, fmt.Errorf("failed to read ktimeEnter")
		}
		printers = gk.argReturnPrinters
	} else {
		ktimeEnter = m.Common.Ktime
		printers = gk.argSigPrinters
	}

	if m.Common.Flags&(processapi.MSG_COMMON_FLAG_KERNEL_STACKTRACE|processapi.MSG_COMMON_FLAG_USER_STACKTRACE) != 0 {
		if m.KernelStackID < 0 {
			logger.GetLogger().Warnf("failed to retrieve kernel stacktrace: id equal to errno %d", m.KernelStackID)
		}
		if m.UserStackID < 0 {
			logger.GetLogger().Debugf("failed to retrieve user stacktrace: id equal to errno %d", m.UserStackID)
		}
		if gk.data.stackTraceMap.MapHandle == nil {
			logger.GetLogger().WithError(err).Warn("failed to load the stacktrace map")
		}
		if m.KernelStackID > 0 || m.UserStackID > 0 {
			// remove the error part
			if m.KernelStackID > 0 {
				id := uint32(m.KernelStackID)
				err = gk.data.stackTraceMap.MapHandle.Lookup(id, &unix.KernelStackTrace)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("failed to lookup the stacktrace map")
				}
			}
			if m.UserStackID > 0 {
				id := uint32(m.UserStackID)
				err = gk.data.stackTraceMap.MapHandle.Lookup(id, &unix.UserStackTrace)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("failed to lookup the stacktrace map")
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
		unix.Args = append(unix.Args, arg)
	}

	// Cache return value on merge and run return filters below before
	// passing up to notify hooks.

	// there are two events for this probe (entry and return)
	if gk.loadArgs.retprobe {
		// if an event exist already, try to merge them. Otherwise, add
		// the one we have in the map.
		curr := pendingEvent{ev: unix, returnEvent: returnEvent}
		key := pendingEventKey{eventId: m.RetProbeId, ktimeEnter: ktimeEnter}

		if prev, exists := gk.pendingEvents.Get(key); exists {
			gk.pendingEvents.Remove(key)
			unix = retprobeMerge(prev, curr)
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

	return []observer.Event{unix}, err
}

func reportMergeError(curr pendingEvent, prev pendingEvent) {
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
	logger.GetLogger().WithFields(logrus.Fields{
		"currFn":   currFn,
		"currType": currType.String(),
		"prevFn":   prevFn,
		"prevType": prevType.String(),
	}).Debugf("failed to merge events")
}

// retprobeMerge merges the two events: the one from the entry probe with the one from the return probe
func retprobeMerge(prev pendingEvent, curr pendingEvent) *tracing.MsgGenericKprobeUnix {
	var retEv, enterEv *tracing.MsgGenericKprobeUnix

	if prev.returnEvent && !curr.returnEvent {
		retEv = prev.ev
		enterEv = curr.ev
	} else if !prev.returnEvent && curr.returnEvent {
		retEv = curr.ev
		enterEv = prev.ev
	} else {
		reportMergeError(curr, prev)
		return nil
	}

	kprobemetrics.MergeOkTotalInc()

	for _, retArg := range retEv.Args {
		index := retArg.GetIndex()
		if uint64(len(enterEv.Args)) > index {
			enterEv.Args[index] = retArg
		} else {
			enterEv.Args = append(enterEv.Args, retArg)
		}
	}
	enterEv.ReturnAction = retEv.Msg.ActionId
	return enterEv
}

func (k *observerKprobeSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadGenericKprobeSensor(args.BPFDir, args.Load, args.Verbose)
}

func selectorsHaveRateLimit(selectors []v1alpha1.KProbeSelector) bool {
	for _, selector := range selectors {
		for _, matchAction := range selector.MatchActions {
			if len(matchAction.RateLimit) > 0 {
				return true
			}
		}
	}
	return false
}

func selectorsHaveStackTrace(selectors []v1alpha1.KProbeSelector) bool {
	for _, selector := range selectors {
		for _, matchAction := range selector.MatchActions {
			if matchAction.KernelStackTrace || matchAction.UserStackTrace {
				return true
			}
		}
	}
	return false
}

func selectorsHaveFDInstall(sel []v1alpha1.KProbeSelector) bool {
	for _, selector := range sel {
		for _, matchAction := range selector.MatchActions {
			if a := selectors.ActionTypeFromString(matchAction.Action); a == selectors.ActionTypeFollowFd ||
				a == selectors.ActionTypeUnfollowFd ||
				a == selectors.ActionTypeCopyFd {
				return true
			}
		}
	}
	return false
}
