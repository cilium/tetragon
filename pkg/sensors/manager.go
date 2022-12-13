// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package sensors

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	sttManager "github.com/cilium/tetragon/pkg/stt"
)

type SensorStatus struct {
	Name    string
	Enabled bool
}

// StartSensorManager initializes the sensorCtlHandle by spawning a sensor
// controller goroutine.
//
// The purpose of this goroutine is to serialize loading and unloading of
// sensors as requested from different goroutines (e.g., different GRPC
// clients).
func StartSensorManager(bpfDir, mapDir, ciliumDir string) (*Manager, error) {
	var m Manager

	c := make(chan sensorOp)
	go func() {

		// map of sensor collections: name -> collection
		sensorCols := map[string]collection{}

		done := false
		for !done {
			op_ := <-c
			// NB: let's keep this to avoid issues from changes. A better approach would
			// be to create functions for each type.
			err := errors.New("BUG in SensorCtl: unset error value") // nolint
			switch op := op_.(type) {

			case *tracingPolicyAdd:
				if _, exists := sensorCols[op.name]; exists {
					err = fmt.Errorf("failed to add tracing policy %s, a sensor collection with the name already exists", op.name)
					break
				}

				var sensors []*Sensor
				for _, s := range registeredSpecHandlers {
					var sensor *Sensor
					spec := op.tp.TpSpec()
					sensor, err = s.SpecHandler(spec)
					if err != nil {
						break
					}
					if sensor == nil {
						continue
					}
					sensors = append(sensors, sensor)
				}

				if err != nil {
					break
				}

				col := collection{
					sensors: sensors,
					name:    op.name,
				}
				err = col.load(op.ctx, bpfDir, mapDir, ciliumDir, nil)
				if err == nil {
					// NB: in some cases it might make
					// sense to keep the policy registered
					// if there was an error. For now,
					// however, we only keep it if it was
					// successfully loaded
					sensorCols[op.name] = col
				}

			case *tracingPolicyDel:
				col, exists := sensorCols[op.name]
				if !exists {
					err = fmt.Errorf("tracing policy %s does not exist", op.name)
					break
				}
				err = col.unload(nil)
				delete(sensorCols, op.name)

			case *sensorAdd:
				if _, exists := sensorCols[op.name]; exists {
					err = fmt.Errorf("sensor %s already exists", op.name)
					break
				}
				sensorCols[op.name] = collection{
					sensors: []*Sensor{op.sensor},
					name:    op.name,
				}
				err = nil

			case *sensorRemove:
				col, exists := sensorCols[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				err = col.unload(nil)
				delete(sensorCols, op.name)

			case *sensorEnable:
				col, exists := sensorCols[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}

				// NB: LoadArg was passed for a previous implementation of a sensor.
				// The idea is that sensors can get a handle to the stt manager when
				// they are loaded which they can use to attach stt information to
				// events. Need to revsit this, and until we do we keep LoadArg.
				err = col.load(op.ctx, bpfDir, mapDir, ciliumDir, &LoadArg{STTManagerHandle: op.sttManagerHandle})

			case *sensorDisable:
				col, exists := sensorCols[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}

				// NB: see LoadArg for sensorEnable
				err = col.unload(&UnloadArg{STTManagerHandle: op.sttManagerHandle})

			case *sensorList:
				ret := make([]SensorStatus, 0)
				for _, col := range sensorCols {
					for _, s := range col.sensors {
						ret = append(ret, SensorStatus{Name: s.Name, Enabled: s.Loaded})
					}
				}
				op.result = &ret
				err = nil

			case *sensorConfigSet:
				col, exists := sensorCols[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				// NB: sensorConfigSet was used before tracing policies were
				// introduced. The idea was that it could be used to provide
				// sensor-specifc configuration values. We can either modify the
				// call to specify a sensor within a collection, or completely
				// remove it. TBD.
				if len(col.sensors) != 1 {
					err = fmt.Errorf("configuration only supported for collections of one sensor, but %s has %d sensors", op.name, len(col.sensors))
					break
				}
				s := col.sensors[0]
				if s.Ops == nil {
					err = fmt.Errorf("sensor %s does not support configuration", op.name)
					break
				}
				err = s.Ops.SetConfig(op.key, op.val)
				if err != nil {
					err = fmt.Errorf("sensor %s SetConfig failed: %w", op.name, err)
					break
				}

			case *sensorConfigGet:
				col, exists := sensorCols[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				// NB: see sensorConfigSet
				if len(col.sensors) != 1 {
					err = fmt.Errorf("configuration only supported for collections of one sensor, but %s has %d sensors", op.name, len(col.sensors))
					break
				}
				s := col.sensors[0]
				if s.Ops == nil {
					err = fmt.Errorf("sensor %s does not support configuration", op.name)
					break
				}
				op.val, err = s.Ops.GetConfig(op.key)
				if err != nil {
					err = fmt.Errorf("sensor %s GetConfig failed: %s", op.name, err)
					break
				}

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

	m.STTManager = sttManager.StartSttManager()
	m.sensorCtl = c
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
	TpSpec() *v1alpha1.TracingPolicySpec
	TpInfo() string
}

// AddTracingPolicy adds a new sensor based on a tracing policy
func (h *Manager) AddTracingPolicy(ctx context.Context, name string, tp TracingPolicy) error {
	retc := make(chan error)
	op := &tracingPolicyAdd{
		ctx:     ctx,
		name:    name,
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
	for n := range registeredSpecHandlers {
		names = append(names, n)
	}
	log.WithField("spec-handlers", strings.Join(names, ", ")).Info("Registered tracing sensors")

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
	tp      TracingPolicy
	retChan chan error
}

type tracingPolicyDel struct {
	ctx     context.Context
	name    string
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
func (s *tracingPolicyAdd) sensorOpDone(e error) { s.retChan <- e }
func (s *tracingPolicyDel) sensorOpDone(e error) { s.retChan <- e }
func (s *sensorAdd) sensorOpDone(e error)        { s.retChan <- e }
func (s *sensorRemove) sensorOpDone(e error)     { s.retChan <- e }
func (s *sensorEnable) sensorOpDone(e error)     { s.retChan <- e }
func (s *sensorDisable) sensorOpDone(e error)    { s.retChan <- e }
func (s *sensorList) sensorOpDone(e error)       { s.retChan <- e }
func (s *sensorConfigSet) sensorOpDone(e error)  { s.retChan <- e }
func (s *sensorConfigGet) sensorOpDone(e error)  { s.retChan <- e }
func (s *sensorCtlStop) sensorOpDone(e error)    { s.retChan <- e }

type sensorCtlHandle = chan<- sensorOp
