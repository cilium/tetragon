// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type SensorStatus struct {
	Name       string
	Enabled    bool
	Collection string
}

// StartSensorManager initializes the sensorCtlHandle by spawning a sensor
// controller goroutine.
//
// The purpose of this goroutine is to serialize loading and unloading of
// sensors as requested from different goroutines (e.g., different GRPC
// clients).
func StartSensorManager(
	bpfDir string,
) (*Manager, error) {
	pfState, err := policyfilter.GetState()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy filter state: %w", err)
	}
	return StartSensorManagerWithPF(bpfDir, pfState)
}

func StartSensorManagerWithPF(
	bpfDir string,
	pfState policyfilter.State,
) (*Manager, error) {
	colMap := newCollectionMap()

	handler, err := newHandler(pfState, colMap, bpfDir)
	if err != nil {
		return nil, err
	}

	m := Manager{
		handler: handler,
	}
	return &m, nil
}

/*
 * Sensor operations
 */

// EnableSensor enables a sensor by name
func (h *Manager) EnableSensor(ctx context.Context, name string) error {
	op := &sensorEnable{
		ctx:  ctx,
		name: name,
	}

	return h.handler.enableSensor(op)
}

// AddSensor adds a sensor
func (h *Manager) AddSensor(ctx context.Context, name string, sensor *Sensor) error {
	op := &sensorAdd{
		ctx:    ctx,
		name:   name,
		sensor: sensor,
	}

	return h.handler.addSensor(op)
}

// DisableSensor disables a sensor by name
func (h *Manager) DisableSensor(ctx context.Context, name string) error {
	op := &sensorDisable{
		ctx:  ctx,
		name: name,
	}

	return h.handler.disableSensor(op)
}

func (h *Manager) ListSensors(ctx context.Context) (*[]SensorStatus, error) {
	op := &sensorList{
		ctx: ctx,
	}

	err := h.handler.listSensors(op)
	if err == nil {
		return op.result, nil
	}
	return nil, err
}

// TracingPolicy is an interface for a tracing policy
// This is implemented by v1alpha1.types.TracingPolicy and
// config.GenericTracingConf. The former is what is the k8s API server uses,
// and the latter is used when we load files directly (e.g., via the cli).
type TracingPolicy interface {
	// TpName returns the name of the policy.
	TpName() string
	// TpSpec  returns the specification of the policy
	TpSpec() *v1alpha1.TracingPolicySpec
	// TpInfo returns a description of the policy
	TpInfo() string
}

// AddTracingPolicy adds a new sensor based on a tracing policy
// NB: if tp implements tracingpolicy.TracingPolicyNamespaced, it will be
// treated as a namespaced policy
func (h *Manager) AddTracingPolicy(ctx context.Context, tp tracingpolicy.TracingPolicy) error {
	var namespace string
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}
	ck := collectionKey{tp.TpName(), namespace}
	op := &tracingPolicyAdd{
		ctx: ctx,
		ck:  ck,
		tp:  tp,
	}

	return h.handler.addTracingPolicy(op)
}

// DeleteTracingPolicy deletes a new sensor based on a tracing policy
func (h *Manager) DeleteTracingPolicy(ctx context.Context, name string, namespace string) error {
	ck := collectionKey{name, namespace}
	op := &tracingPolicyDelete{
		ctx: ctx,
		ck:  ck,
	}

	return h.handler.deleteTracingPolicy(op)
}

func (h *Manager) EnableTracingPolicy(_ context.Context, name, namespace string) error {
	ck := collectionKey{name, namespace}
	var enable = true
	return h.handler.configureTracingPolicy(ck, nil, &enable)
}

func (h *Manager) DisableTracingPolicy(_ context.Context, name, namespace string) error {
	ck := collectionKey{name, namespace}
	var enable = false
	return h.handler.configureTracingPolicy(ck, nil, &enable)
}

func (h *Manager) ConfigureTracingPolicy(_ context.Context, conf *tetragon.ConfigureTracingPolicyRequest) error {
	ck := collectionKey{conf.GetName(), conf.GetNamespace()}
	return h.handler.configureTracingPolicy(ck, conf.Mode, conf.Enable)
}

// ListTracingPolicies returns a list of the active tracing policies
func (h *Manager) ListTracingPolicies(_ context.Context) (*tetragon.ListTracingPoliciesResponse, error) {
	ret := &tetragon.ListTracingPoliciesResponse{}
	ret.Policies = h.handler.listPolicies()
	return ret, nil
}

func (h *Manager) ListOverheads() ([]ProgOverhead, error) {
	return h.handler.listOverheads()
}

func (h *Manager) RemoveSensor(ctx context.Context, sensorName string) error {
	op := &sensorRemove{
		ctx:   ctx,
		name:  sensorName,
		unpin: true,
	}

	return h.handler.removeSensor(op)
}

func (h *Manager) RemoveAllSensors(ctx context.Context) error {
	op := &sensorRemove{
		ctx:   ctx,
		all:   true,
		unpin: !option.Config.KeepSensorsOnExit,
	}

	return h.handler.removeSensor(op)
}

func (h *Manager) LogSensorsAndProbes(ctx context.Context) {
	log := logger.GetLogger()
	sensors, err := h.ListSensors(ctx)
	if err != nil {
		log.WithError(err).Warn("failed to list sensors")
	}

	names := []string{}
	for _, s := range *sensors {
		names = append(names, s.Name)
	}
	log.WithField("sensors", strings.Join(names, ", ")).Info("Available sensors")

	names = []string{}
	for n := range registeredPolicyHandlers {
		names = append(names, n)
	}
	log.WithField("policy-handlers", strings.Join(names, ", ")).Info("Registered sensors (policy-handlers)")

	names = []string{}
	for n := range registeredProbeLoad {
		names = append(names, n)
	}
	log.WithField("types", strings.Join(names, ", ")).Info("Registered probe types")
}

// Manager handles dynamic sensor management, such as adding / removing sensors
// at runtime.
type Manager struct {
	// channel to communicate with the controller goroutine
	handler *handler
}

// tracingPolicyAdd adds a sensor based on a the provided tracing policy
type tracingPolicyAdd struct {
	ctx context.Context
	ck  collectionKey
	tp  tracingpolicy.TracingPolicy
}

type tracingPolicyDelete struct {
	ctx context.Context
	ck  collectionKey
}

// sensorAdd adds a sensor
type sensorAdd struct {
	ctx    context.Context
	name   string
	sensor *Sensor
}

// sensorRemove removes a sensor (for now, used only for tracing policies)
type sensorRemove struct {
	ctx   context.Context
	name  string
	all   bool
	unpin bool
}

// sensorEnable enables a sensor
type sensorEnable struct {
	ctx  context.Context
	name string
}

// sensorDisable disables a sensor
type sensorDisable struct {
	ctx  context.Context
	name string
}

// sensorList returns a list of the active sensors
type sensorList struct {
	ctx    context.Context
	result *[]SensorStatus
}
