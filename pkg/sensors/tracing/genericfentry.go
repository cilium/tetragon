// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type observerFentrySensor struct {
	name string
}

func init() {
	fentry := &observerFentrySensor{
		name: "kprobe sensor",
	}
	sensors.RegisterProbeType("generic_fentry", fentry)
}

func createGenericFentrySensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
	valInfo []*kpValidateInfo,
) (*sensors.Sensor, error) {

	// TODO support enforcement ;-)
	for _, fentry := range spec.Fentries {
		if selectors.HasEnforcementAction(fentry.Selectors) {
			return nil, errors.New("enforcement is not supported for fentry yet")
		}
	}

	return createGenericKprobeSensorFlag(spec, name, polInfo, valInfo, true)
}

func (k *observerFentrySensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadGenericFentrySensor(args.BPFDir, args.Load, args.Maps, args.Verbose)
}

func loadGenericFentrySensor(bpfDir string, load *program.Program, maps []*program.Map, verbose int) error {
	if id, ok := load.LoaderData.(idtable.EntryID); ok {
		return loadSingleKprobeSensor(id, bpfDir, load, maps, verbose, true)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}
