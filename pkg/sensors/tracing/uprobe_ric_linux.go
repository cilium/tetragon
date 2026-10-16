// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"fmt"
	"os"
	"path"
	"slices"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// createResolvePathInContainerSensor builds the policy's parent sensor. It
// loads the uprobes on host paths and owns the policy maps its per-binary
// children share, and between PostLoad and PreUnload attaches each
// resolvePathInContainer uprobe to the containers the policyfilter reports.
func createResolvePathInContainerSensor(spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo) (*sensors.Sensor, error) {
	sensor, err := createGenericUprobeSensor(spec, "generic_uprobe", polInfo, nil)
	if err != nil {
		return nil, err
	}
	// Maps the parent loads come from the object the per-binary sensors
	// load, so the pins match theirs.
	useMulti := !polInfo.specOpts.DisableUprobeMulti && bpf.HasUprobeMulti()
	loadProgName, _ := config.GenericUprobeObjs(useMulti)
	template := program.Builder(path.Join(option.Config.HubbleLib, loadProgName),
		"resolvePathInContainer maps", "", "", "generic_uprobe").SetPolicy(polInfo.name)
	// Without a program of its own, the parent loads the policy maps itself,
	// and the loader never runs the policy_conf initializer.
	var policyConf *program.Map
	if len(sensor.Progs) == 0 {
		policyConf = polInfo.policyConfMap(template)
		sensor.Maps = append(sensor.Maps, policyConf, polInfo.selectorStatsMap(template))
		// Its uprobes attach through the per-binary sensors, which report
		// the policy mode and stats through these maps.
		sensor.NoHooksAttached = false
	}
	held, err := heldSharedMaps(spec, polInfo, template, useMulti)
	if err != nil {
		return nil, err
	}
	sensor.Maps = append(sensor.Maps, held...)

	var (
		recs    []*containerUprobeReconciler
		unwatch func()
	)
	stop := func() {
		for _, rec := range recs {
			rec.stop()
		}
		recs = nil
	}
	postLoad := sensor.PostLoadHook
	sensor.PostLoadHook = func() error {
		if err := postLoad(); err != nil {
			return err
		}
		if policyConf != nil {
			for _, ml := range template.MapLoad {
				if err := ml.Load(policyConf.MapHandle, policyConf.PinPath); err != nil {
					return err
				}
			}
		}
		pf, err := policyfilter.GetState()
		if err != nil {
			return err
		}
		if !option.Config.EnableCRI {
			logger.GetLogger().Warn("uprobe resolvePathInContainer: CRI is disabled, so only containers "+
				"reported by runtime hooks are traced", "policy", polInfo.name)
		}
		for i := range spec.UProbes {
			if !spec.UProbes[i].ResolvePathInContainer {
				continue
			}
			recs = append(recs, newContainerUprobeReconciler(fmt.Sprintf("generic_uprobe_ric_%d", i),
				spec.UProbes[i].Path, sensor.BpfDir, containerUprobeSensorBuilder(polInfo, spec, i), containerRootFor))
		}
		// A policy has one watcher, so it feeds every uprobe's reconciler.
		unwatch, err = pf.WatchPolicyContainers(polInfo.policyID, func(c policyfilter.ContainerChange) {
			for _, rec := range recs {
				rec.push(c)
			}
		})
		if err != nil {
			stop()
			return err
		}
		return nil
	}
	sensor.PreUnloadHook = func() error {
		if recs != nil {
			unwatch()
			stop()
		}
		return nil
	}
	return sensor, nil
}

// heldSharedMaps returns the maps shared by all uprobe sensors that the
// per-binary sensors use. Those load outside the sensor manager, so the policy
// sensor loads these maps once under the manager, and the per-binary sensors
// only use them.
func heldSharedMaps(spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo, load *program.Program, useMulti bool) ([]*program.Map, error) {
	has := uprobeHas{
		sleepablePreloadSize: polInfo.specOpts.SleepablePreloadSize,
		sleepableOffloadSize: polInfo.specOpts.SleepableOffloadSize,
		uprobeHeapSize:       polInfo.specOpts.UprobeHeapSize,
	}
	for i := range spec.UProbes {
		if !spec.UProbes[i].ResolvePathInContainer {
			continue
		}
		u, err := expandedUprobe(spec, &spec.UProbes[i])
		if err != nil {
			return nil, err
		}
		if err := validateUprobeConfig(u, &addUprobeIn{}, &has); err != nil {
			return nil, err
		}
	}

	var maps []*program.Map
	if useMulti && has.uprobeHeapSize == 0 {
		for _, name := range uprobeHeapMaps {
			maps = append(maps, getUprobeHeapMap(name, 0, false, load))
		}
	}
	if has.sleepableOffload && has.sleepableOffloadSize == 0 {
		maps = append(maps, getSleepableOffloadMap(0, false, load))
	}
	if has.sleepablePreload && has.sleepablePreloadSize == 0 {
		maps = append(maps, getSleepablePreloadMap(0, false, load))
	}
	return maps, nil
}

// containerUprobeSpec copies the parent's spec for the per-container sensor
// of the uprobe at index. Every uprobe is kept, so that one keeps its index
// and selector stats offset, and its in-container Path so events report it.
func containerUprobeSpec(parent *v1alpha1.TracingPolicySpec, index int) *v1alpha1.TracingPolicySpec {
	uprobes := slices.Clone(parent.UProbes)
	// Macro expansion mutates Selectors, so never share those it expands.
	parent.UProbes[index].DeepCopyInto(&uprobes[index])
	return &v1alpha1.TracingPolicySpec{
		UProbes:         uprobes,
		Options:         parent.Options,
		SelectorsMacros: parent.SelectorsMacros,
		Lists:           parent.Lists,
	}
}

func containerUprobeSensorBuilder(polInfo *policyInfo, parent *v1alpha1.TracingPolicySpec, index int) sensorBuilder {
	return func(name string, binary *os.File) (loadedSensor, error) {
		sensor, err := createGenericUprobeSensor(containerUprobeSpec(parent, index), name, polInfo,
			&containerUprobe{index: index, binary: binary})
		if err != nil {
			return nil, err
		}
		return sensor, nil
	}
}
