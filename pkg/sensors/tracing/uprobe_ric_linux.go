// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"os"
	"path"
	"time"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const criTimeout = 5 * time.Second

// createResolvePathInContainerSensor builds the policy's parent sensor. It
// loads no program but owns the policy maps its per-binary children share,
// and attaches those children to the containers the policyfilter reports
// between PostLoad and PreUnload.
func createResolvePathInContainerSensor(spec *v1alpha1.TracingPolicySpec, uprobe *v1alpha1.UProbeSpec, polInfo *policyInfo) (*sensors.Sensor, error) {
	loadProgName, _ := config.GenericUprobeObjs(false)
	template := program.Builder(path.Join(option.Config.HubbleLib, loadProgName),
		"resolvePathInContainer policy maps", "", "", "generic_uprobe").SetPolicy(polInfo.name)
	policyConf := polInfo.policyConfMap(template)

	sensor := &sensors.Sensor{
		Name:            "generic_uprobe",
		Policy:          polInfo.name,
		Namespace:       polInfo.namespace,
		Maps:            []*program.Map{policyConf, polInfo.selectorStatsMap(template)},
		NoHooksAttached: true,
	}
	var (
		rec     *containerUprobeReconciler
		unwatch func()
	)
	sensor.PostLoadHook = func() error {
		// The parent loads no program, so the loader never runs the
		// policy_conf initializer.
		for _, ml := range template.MapLoad {
			if err := ml.Load(policyConf.MapHandle, policyConf.PinPath); err != nil {
				return err
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
		procFS := option.Config.ProcFS
		rec = newContainerUprobeReconciler(procFS, uprobe.Path, sensor.BpfDir,
			containerUprobeSensorBuilder(polInfo, spec, uprobe),
			func(ctx context.Context, c policyfilter.ContainerChange) (*containerRoot, error) {
				if c.RootDir != "" {
					root, err := containerRootFromHook(procFS, c.RootDir)
					if err == nil {
						return root, nil
					}
					// The runtime's root may not be procFS's, as in a kind node.
					logger.GetLogger().Debug("uprobe resolvePathInContainer: runtime hook root unusable, asking CRI",
						logfields.Error, err, "container", c.ContainerID)
				}
				ctx, cancel := context.WithTimeout(ctx, criTimeout)
				defer cancel()
				return containerRootFromCRI(ctx, procFS, c.ContainerID)
			})
		unwatch, err = pf.WatchPolicyContainers(polInfo.policyID, rec.push)
		if err != nil {
			rec.stop()
			rec = nil
			return err
		}
		return nil
	}
	sensor.PreUnloadHook = func() error {
		if rec != nil {
			unwatch()
			rec.stop()
			rec = nil
		}
		return nil
	}
	return sensor, nil
}

// containerUprobeSpec builds a child spec from the parent's single uprobe. It
// keeps the in-container Path so events report it.
func containerUprobeSpec(parent *v1alpha1.TracingPolicySpec, uprobe *v1alpha1.UProbeSpec) *v1alpha1.TracingPolicySpec {
	return &v1alpha1.TracingPolicySpec{
		// Macro expansion mutates Selectors, so never share them.
		UProbes:         []v1alpha1.UProbeSpec{*uprobe.DeepCopy()},
		Options:         parent.Options,
		SelectorsMacros: parent.SelectorsMacros,
		Lists:           parent.Lists,
	}
}

func containerUprobeSensorBuilder(polInfo *policyInfo, parent *v1alpha1.TracingPolicySpec, uprobe *v1alpha1.UProbeSpec) sensorBuilder {
	return func(name string, binary *os.File) (loadedSensor, error) {
		sensor, err := createGenericUprobeSensor(containerUprobeSpec(parent, uprobe), name, polInfo, binary)
		if err != nil {
			return nil, err
		}
		return sensor, nil
	}
}
