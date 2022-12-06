// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package sensors

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
		done := false
		for !done {
			op_ := <-c
			err := errors.New("BUG in SensorCtl: unset error value")
			switch op := op_.(type) {

			case *tracingPolicyAdd:
				var sensor *Sensor
				if _, exists := availableSensors[op.sensorName]; exists {
					err = fmt.Errorf("sensor %s already exists", op.sensorName)
					break
				}
				sensors := []*Sensor{}
				for _, s := range registeredSpecHandlers {
					sensor, err = s.SpecHandler(op.spec)
					if err != nil {
						break
					}
					if sensor == nil {
						continue
					}
					if err = sensor.FindPrograms(op.ctx); err != nil {
						err = fmt.Errorf("sensor %s could not be found", op.sensorName)
						break
					}
					err = sensor.Load(op.ctx, bpfDir, mapDir, ciliumDir)
					if err != nil {
						break
					}
					sensors = append(sensors, sensor)
				}
				availableSensors[op.sensorName] = sensors

			case *tracingPolicyDel:
				sensors, exists := availableSensors[op.sensorName]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.sensorName)
					break
				}
				errs := []string{}
				for _, s := range sensors {
					if !s.Loaded {
						continue
					}
					if err = s.Unload(); err != nil {
						errs = append(errs, err.Error())
					}
				}
				if len(errs) > 0 {
					err = fmt.Errorf("errors unloading sensor %s: %s", op.sensorName, strings.Join(errs, ", "))
				}
				delete(availableSensors, op.sensorName)

			case *sensorAdd:
				if _, exists := availableSensors[op.name]; exists {
					err = fmt.Errorf("sensor %s already exists", op.name)
					break
				}
				availableSensors[op.name] = []*Sensor{op.sensor}
				err = nil

			case *sensorRemove:
				sensors, exists := availableSensors[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				err = nil
				for _, s := range sensors {
					if s.Loaded {
						err = fmt.Errorf("sensor %s enabled, please disable it before removing", op.name)
						break
					}
				}
				if err == nil {
					delete(availableSensors, op.name)
				}
			case *sensorEnable:
				sensors, exists := availableSensors[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}

				err = nil
				for _, s := range sensors {
					// NB: For now, we don't treat a sensor already loaded as an error
					// because that would complicate the client side, but we might have
					// to reconsider
					if s.Loaded {
						logger.GetLogger().Infof("ignoring enableSensor %s since sensor is already enabled", s.Name)
						continue
					}
					err = s.Load(op.ctx, bpfDir, mapDir, ciliumDir)
					if err == nil && s.Ops != nil {
						s.Ops.Loaded(LoadArg{STTManagerHandle: op.sttManagerHandle})
					}
				}

			case *sensorDisable:
				sensors, exists := availableSensors[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				// NB: ditto as sensorEnable
				err = nil
				for _, s := range sensors {
					if !s.Loaded {
						logger.GetLogger().Infof("ignoring disableSensor %s since sensor is not enabled", s.Name)
						continue
					}
					err = s.Unload()
					if err == nil && s.Ops != nil {
						s.Ops.Unloaded(UnloadArg{STTManagerHandle: op.sttManagerHandle})
					}
				}

			case *sensorList:
				ret := make([]SensorStatus, 0, len(availableSensors))
				for n, sl := range availableSensors {
					for _, s := range sl {
						ret = append(ret, SensorStatus{Name: n, Enabled: s.Loaded})
					}
				}
				op.result = &ret
				err = nil

			case *sensorConfigSet:
				sensors, exists := availableSensors[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				for _, s := range sensors {
					if s.Ops == nil {
						err = fmt.Errorf("sensor %s does not support configuration", op.name)
						break
					}
					err = s.Ops.SetConfig(op.key, op.val)
					if err != nil {
						err = fmt.Errorf("sensor %s SetConfig failed: %w", op.name, err)
						break
					}
				}

			case *sensorConfigGet:
				sensors, exists := availableSensors[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				for _, s := range sensors {
					if s.Ops == nil {
						err = fmt.Errorf("sensor %s does not support configuration", op.name)
						break
					}
					op.val, err = s.Ops.GetConfig(op.key)
					if err != nil {
						err = fmt.Errorf("sensor %s GetConfig failed: %s", op.name, err)
						break
					}
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

// AddTracingPolicy adds a new sensor based on a tracing policy
func (h *Manager) AddTracingPolicy(ctx context.Context, sensorName string, spec interface{}) error {
	retc := make(chan error)
	op := &tracingPolicyAdd{
		ctx:        ctx,
		sensorName: sensorName,
		spec:       spec,
		retChan:    retc,
	}

	h.sensorCtl <- op
	err := <-retc

	return err
}

// DelTracingPolicy deletes a new sensor based on a tracing policy
func (h *Manager) DelTracingPolicy(ctx context.Context, sensorName string) error {
	retc := make(chan error)
	op := &tracingPolicyDel{
		ctx:        ctx,
		sensorName: sensorName,
		retChan:    retc,
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
	ctx        context.Context
	sensorName string
	spec       interface{}
	retChan    chan error
}

type tracingPolicyDel struct {
	ctx        context.Context
	sensorName string
	retChan    chan error
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
