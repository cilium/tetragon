// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package sensors

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	sttManager "github.com/cilium/tetragon/pkg/stt"
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
//
// if waitChan is not nil, the serving of sensor requests will block until
// something is received. The intention of this is to allow the main function
// to first load the base sensor before the sensor manager starts loading other sensors.
func StartSensorManager(
	bpfDir, mapDir, ciliumDir string,
	waitChan chan struct{},
) (*Manager, error) {
	c := make(chan sensorOp)
	m := Manager{
		STTManager: sttManager.StartSttManager(),
		sensorCtl:  c,
	}
	handler, err := newHandler(bpfDir, mapDir, ciliumDir)
	if err != nil {
		return nil, err
	}

	go func() {

		// wait until start serving requests
		if waitChan != nil {
			logger.GetLogger().Infof("sensor controller waiting on channel")
			<-waitChan
			logger.GetLogger().Infof("sensor controller starts")
		}

		done := false
		for !done {
			op_ := <-c
			err := errors.New("BUG in SensorCtl: unset error value") // nolint
			switch op := op_.(type) {
			case *tracingPolicyAdd:
				err = handler.addTracingPolicy(op)
			case *tracingPolicyDel:
				err = handler.delTracingPolicy(op)
			case *tracingPolicyList:
				err = handler.listTracingPolicies(op)
			case *sensorAdd:
				err = handler.addSensor(op)
			case *sensorRemove:
				err = handler.removeSensor(op)
			case *sensorEnable:
				err = handler.enableSensor(op)
			case *sensorDisable:
				err = handler.disableSensor(op)
			case *sensorList:
				err = handler.listSensors(op)
			case *sensorConfigSet:
				err = handler.configSet(op)
			case *sensorConfigGet:
				err = handler.configGet(op)
			case *sensorCtlStop:
				logger.GetLogger().Debugf("stopping sensor controller...")
				done = true
				err = nil
			default:
				err = fmt.Errorf("unknown sensorOp: %v", op)
			}
			op_.sensorOpDone(err)
		}
	}()
	return &m, nil
}

/*
 * Sensor operations
 */

// EnableSensor enables a sensor by name
func (h *Manager) EnableSensor(ctx context.Context, name string) error {
	retc := make(chan error)
	op := &sensorEnable{
		ctx:              ctx,
		name:             name,
		sttManagerHandle: h.STTManager,
		retChan:          retc,
	}

	h.sensorCtl <- op
	err := <-retc

	return err
}

// AddSensor adds a sensor
func (h *Manager) AddSensor(ctx context.Context, name string, sensor *Sensor) error {
	retc := make(chan error)
	op := &sensorAdd{
		ctx:     ctx,
		name:    name,
		sensor:  sensor,
		retChan: retc,
	}

	h.sensorCtl <- op
	return <-retc
}

// DisableSensor disables a sensor by name
func (h *Manager) DisableSensor(ctx context.Context, name string) error {
	retc := make(chan error)
	op := &sensorDisable{
		ctx:              ctx,
		name:             name,
		sttManagerHandle: h.STTManager,
		retChan:          retc,
	}

	h.sensorCtl <- op
	return <-retc
}

func (h *Manager) ListSensors(ctx context.Context) (*[]SensorStatus, error) {
	retc := make(chan error)
	op := &sensorList{
		ctx:     ctx,
		retChan: retc,
	}

	h.sensorCtl <- op
	err := <-retc
	if err == nil {
		return op.result, nil
	}

	return nil, err
}

func (h *Manager) GetSensorConfig(ctx context.Context, name string, cfgkey string) (string, error) {
	retc := make(chan error)
	op := &sensorConfigGet{
		ctx:     ctx,
		name:    name,
		key:     cfgkey,
		retChan: retc,
	}

	h.sensorCtl <- op
	err := <-retc
	if err == nil {
		return op.val, nil
	}

	return "", err
}

func (h *Manager) SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error {
	retc := make(chan error)
	op := &sensorConfigSet{
		ctx:     ctx,
		name:    name,
		key:     cfgkey,
		val:     cfgval,
		retChan: retc,
	}

	h.sensorCtl <- op
	return <-retc
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
	retc := make(chan error)
	op := &tracingPolicyAdd{
		ctx:     ctx,
		name:    tp.TpName(),
		tp:      tp,
		retChan: retc,
	}

	h.sensorCtl <- op
	err := <-retc

	return err
}

// DelTracingPolicy deletes a new sensor based on a tracing policy
func (h *Manager) DelTracingPolicy(ctx context.Context, name string) error {
	retc := make(chan error)
	op := &tracingPolicyDel{
		ctx:     ctx,
		name:    name,
		retChan: retc,
	}

	h.sensorCtl <- op
	err := <-retc

	return err
}

// ListTracingPolicies returns a list of the active tracing policies
func (h *Manager) ListTracingPolicies(ctx context.Context) (*tetragon.ListTracingPoliciesResponse, error) {
	retc := make(chan error)
	op := &tracingPolicyList{
		ctx:     ctx,
		retChan: retc,
	}

	h.sensorCtl <- op
	err := <-retc
	return op.result, err
}

func (h *Manager) RemoveSensor(ctx context.Context, sensorName string) error {
	retc := make(chan error)
	op := &sensorRemove{
		ctx:     ctx,
		name:    sensorName,
		retChan: retc,
	}

	h.sensorCtl <- op
	err := <-retc

	return err
}

func (h *Manager) StopSensorManager(ctx context.Context) error {
	retc := make(chan error)
	op := &sensorCtlStop{
		ctx:     ctx,
		retChan: retc,
	}

	h.sensorCtl <- op
	return <-retc
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
	sensorCtl  sensorCtlHandle
	STTManager sttManager.Handle
}

// There are 6 commands that can be passed to the controller goroutine:
// - tracingPolicyAdd
// - tracingPolicyDel
// - sensorList
// - sensorEnable
// - sensorDisable
// - sensorRemove
// - sensorCtlStop

// tracingPolicyAdd adds a sensor based on a the provided tracing policy
type tracingPolicyAdd struct {
	ctx     context.Context
	name    string
	tp      tracingpolicy.TracingPolicy
	retChan chan error
}

type tracingPolicyDel struct {
	ctx     context.Context
	name    string
	retChan chan error
}

type tracingPolicyList struct {
	ctx     context.Context
	result  *tetragon.ListTracingPoliciesResponse
	retChan chan error
}

// sensorOp is an interface for the sensor operations.
// Not strictly needed but allows for better type checking.
type sensorOp interface {
	sensorOpDone(error)
}

// sensorAdd adds a sensor
type sensorAdd struct {
	ctx     context.Context
	name    string
	sensor  *Sensor
	retChan chan error
}

// sensorRemove removes a sensor (for now, used only for tracing policies)
type sensorRemove struct {
	ctx     context.Context
	name    string
	retChan chan error
}

// sensorEnable enables a sensor
type sensorEnable struct {
	ctx              context.Context
	name             string
	sttManagerHandle sttManager.Handle
	retChan          chan error
}

// sensorDisable disables a sensor
type sensorDisable struct {
	ctx              context.Context
	name             string
	sttManagerHandle sttManager.Handle
	retChan          chan error
}

// sensorList returns a list of the active sensors
type sensorList struct {
	ctx     context.Context
	result  *[]SensorStatus
	retChan chan error
}

// set a configuration option on a sensor
type sensorConfigSet struct {
	ctx     context.Context
	name    string
	key     string
	val     string
	retChan chan error
}

// get a configuration option on a sensor
type sensorConfigGet struct {
	ctx     context.Context
	name    string
	key     string
	val     string
	retChan chan error
}

// sensorCtlStop stops the controller
type sensorCtlStop struct {
	ctx     context.Context
	retChan chan error
}

type LoadArg struct {
	STTManagerHandle sttManager.Handle
}
type UnloadArg = LoadArg

// trivial sensorOpDone implementations for commands
func (s *tracingPolicyAdd) sensorOpDone(e error)  { s.retChan <- e }
func (s *tracingPolicyDel) sensorOpDone(e error)  { s.retChan <- e }
func (s *tracingPolicyList) sensorOpDone(e error) { s.retChan <- e }
func (s *sensorAdd) sensorOpDone(e error)         { s.retChan <- e }
func (s *sensorRemove) sensorOpDone(e error)      { s.retChan <- e }
func (s *sensorEnable) sensorOpDone(e error)      { s.retChan <- e }
func (s *sensorDisable) sensorOpDone(e error)     { s.retChan <- e }
func (s *sensorList) sensorOpDone(e error)        { s.retChan <- e }
func (s *sensorConfigSet) sensorOpDone(e error)   { s.retChan <- e }
func (s *sensorConfigGet) sensorOpDone(e error)   { s.retChan <- e }
func (s *sensorCtlStop) sensorOpDone(e error)     { s.retChan <- e }

type sensorCtlHandle = chan<- sensorOp
