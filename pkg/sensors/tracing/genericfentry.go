// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/cilium/tetragon/pkg/celbpf"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func resolveFentryMultiBTFIDs(valInfo []*kpValidateInfo) (map[string]btf.TypeID, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("loading kernel BTF: %w", err)
	}

	ids := make(map[string]btf.TypeID)
	for _, info := range valInfo {
		if info.ignore {
			continue
		}
		for _, call := range info.calls {
			if _, exists := ids[call]; exists {
				return nil, fmt.Errorf("function %q is configured more than once", call)
			}
			types, err := spec.AnyTypesByName(call)
			if err != nil {
				return nil, fmt.Errorf("looking up BTF ID for %q: %w", call, err)
			}

			var fn *btf.Func
			for _, typ := range types {
				if candidate, ok := typ.(*btf.Func); ok {
					fn = candidate
					break
				}
			}
			if fn == nil {
				return nil, fmt.Errorf("looking up BTF ID for %q: %w", call, btf.ErrNotFound)
			}
			id, err := spec.TypeID(fn)
			if err != nil {
				return nil, fmt.Errorf("looking up BTF ID for %q: %w", call, err)
			}
			ids[call] = id
		}
	}
	return ids, nil
}

type observerFentrySensor struct {
	name string
}

func init() {
	fentry := &observerFentrySensor{
		name: "fentrry sensor",
	}
	sensors.RegisterProbeType("generic_fentry", fentry)
}

func canUseFentry(kprobes []v1alpha1.KProbeSpec, useKprobesAsFentries bool) bool {
	if !useKprobesAsFentries {
		return false
	}

	for _, fentry := range kprobes {
		if selectors.HasEnforcementAction(fentry.Selectors) {
			return false
		}
	}
	return true
}

func createGenericFentrySensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
	valInfo []*kpValidateInfo,
) (*sensors.Sensor, error) {

	// TODO support enforcement ;-)
	if !canUseFentry(spec.Fentries, true) {
		return nil, errors.New("enforcement is not supported for fentry yet")
	}

	return createGenericKprobeSensor(spec, name, polInfo, valInfo, fentry)
}

func (k *observerFentrySensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadGenericFentrySensor(args.BPFDir, args.Load, args.Maps, args.Verbose)
}

func loadMultiFentrySensor(ids []idtable.EntryID, bpfDir string, load *program.Program, maps []*program.Map, verbose int) error {
	binBuf := make([]bytes.Buffer, len(ids))
	data := &program.TracingMultiAttachData{}

	rewriteName := "generic_fentry_filter_arg"
	if load.RetProbe {
		rewriteName = "generic_fexit_filter_arg"
	}

	var celFns selectors.CelExprFunctions

	for index, id := range ids {
		gk, err := genericKprobeTableGet(id)
		if err != nil {
			return err
		}

		if gk.btfID == 0 {
			return fmt.Errorf("missing tracing_multi BTF ID for %q", gk.funcName)
		}

		if selector := getProgramSelector(load, gk); selector != nil && celbpf.EnabledInBPF() {
			if cefs := selector.CelExprFunctions(); cefs != nil {
				celFns = *cefs
			}
		}

		load.MapLoad = append(load.MapLoad, getMapLoad(load, gk, uint32(index))...)

		if err := binary.Write(&binBuf[index], binary.LittleEndian, gk.loadArgs.config); err != nil {
			return fmt.Errorf("writing config for %q: %w", gk.funcName, err)
		}

		config := &program.MapLoad{
			Name: "config_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(uint32(index), binBuf[index].Bytes(), ebpf.UpdateAny)
			},
		}
		load.MapLoad = append(load.MapLoad, config)

		data.BTFIDs = append(data.BTFIDs, gk.btfID)
		data.Cookies = append(data.Cookies, uint64(index))
	}

	load.RewriteProg = map[string]func(*ebpf.ProgramSpec) error{
		rewriteName: celFns.RewriteProg,
	}
	load.SetAttachData(data)
	if err := program.LoadTracingMultiProgram(bpfDir, load, maps, verbose); err != nil {
		return err
	}
	logger.GetLogger().Info(fmt.Sprintf("Loaded generic fentry multi sensor: %s -> %s", load.Name, load.Attach))
	return nil
}

func loadGenericFentrySensor(bpfDir string, load *program.Program, maps []*program.Map, verbose int) error {
	if id, ok := load.LoaderData.(idtable.EntryID); ok {
		return loadSingleKprobeSensor(id, bpfDir, load, maps, verbose, true)
	}
	if ids, ok := load.LoaderData.([]idtable.EntryID); ok {
		return loadMultiFentrySensor(ids, bpfDir, load, maps, verbose)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID/[] and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}
