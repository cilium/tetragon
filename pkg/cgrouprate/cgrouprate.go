// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// cgrouprate - user space part of cgroup rate monitoring
//
// In nutshell we compute/monitor the rate per cpu via ebpf cgroup_rate
// function (bpf/process/bpf_rate.h) that sends throttle event to user
// space when the rate for cgroup crosses limit on the given cpu.
//
// At the moment we monitor cgroup rate for exec/fork/exit events.
//
// The user space (cgrouprate object) then triggers throttle start event
// and starts timer to periodically check on the cgroup rate. When the
// rate goes down or the cpu gets idle (and all other cpus rates are ok)
// we send throttle stop event.
//
// Having throttle start event means that one or more cpus that execute
// cgroup code crossed the limit and are throttled (paused).
// Having throttle stop events means that all previously throttled cpus
// are now below allowed limit rate and sends events.

package cgrouprate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics/cgroupratemetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	aliveCnt            = 5
	cleanupInterval     = time.Minute
	cleanupInactiveTime = time.Minute
	cgRateMaxEntries    = 32768 // this value could be fine tuned
)

type globalState struct {
	cgRateMap        *program.Map
	cgRateOptionsMap *program.Map

	handle *CgroupRate
	mu     sync.RWMutex
}

var glSt globalState

type cgroupQueue struct {
	id    uint64
	ktime uint64
	name  string
}

type CgroupRate struct {
	listener observer.Listener
	log      logger.FieldLogger
	ch       chan *cgroupQueue
	opts     *option.CgroupRate
	hash     *program.Map
	cgroups  map[uint64]string
	cleanup  time.Duration
}

func newCgroupRate(
	listener observer.Listener,
	hash *program.Map,
	opts *option.CgroupRate) *CgroupRate {

	return &CgroupRate{
		listener: listener,
		log:      logger.GetLogger(),
		cgroups:  make(map[uint64]string),
		ch:       make(chan *cgroupQueue),
		hash:     hash,
		opts:     opts,
	}
}

func NewCgroupRate(ctx context.Context,
	listener observer.Listener,
	opts *option.CgroupRate) error {

	if opts.Events == 0 || opts.Interval == 0 {
		logger.GetLogger().Info(fmt.Sprintf("Cgroup rate disabled (%d/%s)", opts.Events, time.Duration(opts.Interval).String()))
		return nil
	}

	glSt.mu.Lock()
	defer glSt.mu.Unlock()
	if glSt.cgRateMap == nil {
		return errors.New("cgrouprate has not been registered to base sensor")
	}

	glSt.handle = newCgroupRate(listener, glSt.cgRateMap, opts)
	go glSt.handle.process(ctx)
	return nil
}

func NewTestCgroupRate(listener observer.Listener,
	hash *program.Map,
	opts *option.CgroupRate) {

	glSt.handle = newCgroupRate(listener, hash, opts)
}

func (r *CgroupRate) notify(msg notify.Message) {
	if err := r.listener.Notify(msg); err != nil {
		r.log.Warn("failed to notify listener", logfields.Error, err)
	}
}

func (r *CgroupRate) process(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	r.log.Info(fmt.Sprintf("Cgroup rate started (%d/%s)", r.opts.Events, time.Duration(r.opts.Interval).String()))

	defer func() {
		// cleanup
		glSt.handle = nil
	}()

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case cq := <-r.ch:
			r.updateCgroups(cq)
		case <-ticker.C:
			r.processCgroups()
		}
	}
}

func (r *CgroupRate) updateCgroups(cq *cgroupQueue) {
	if _, ok := r.cgroups[cq.id]; ok {
		// the group is guaranteed to be checked on next timer
		return
	}

	r.cgroups[cq.id] = cq.name

	// start throttle event
	r.notify(&tracing.MsgProcessThrottleUnix{
		Type:   tetragon.ThrottleType_THROTTLE_START,
		Cgroup: cq.name,
		Ktime:  cq.ktime,
	})
	cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.ThrottleStart)
}

func (r *CgroupRate) processCgroups() {
	var remove []uint64

	if r.hash.MapHandle == nil {
		return
	}

	last, err := ktime.Monotonic()
	if err != nil {
		return
	}

	for id, cgroup := range r.cgroups {
		if r.processCgroup(id, cgroup, uint64(last)) {
			remove = append(remove, id)
		}
	}

	for _, id := range remove {
		delete(r.cgroups, id)
	}

	r.cleanupCgroups(last)
}

func (r *CgroupRate) cleanupCgroups(curr time.Duration) {
	if r.cleanup == 0 {
		r.cleanup = curr
		return
	}
	// Run the cleanup once per cleanupInterval time
	if curr-r.cleanup < cleanupInterval {
		return
	}
	r.cleanup = curr

	hash := r.hash.MapHandle
	key := processapi.CgroupRateKey{}
	values := make([]processapi.CgroupRateValue, bpf.GetNumPossibleCPUs())

	entries := hash.Iterate()
	for entries.Next(&key, &values) {
		remove := true
		// Remove values that are inactive for longer than cleanupInactiveTime time
		for _, val := range values {
			if time.Duration(val.Time)+cleanupInactiveTime > curr {
				remove = false
			}
		}
		if remove {
			if err := hash.Delete(key); err != nil {
				cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.DeleteFail)
			} else {
				cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.Delete)
			}
		}
	}
}

func (r *CgroupRate) processCgroup(id uint64, cgroup string, last uint64) bool {
	key := processapi.CgroupRateKey{
		ID: id,
	}
	values := make([]processapi.CgroupRateValue, bpf.GetNumPossibleCPUs())

	hash := r.hash.MapHandle
	cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.Process)

	if err := hash.Lookup(key, &values); err != nil {
		cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.LookupFail)
		// cgroup got likely removed, remove it as well
		return true
	}

	stop := true

	for _, val := range values {
		// cpu is silent long enough
		if last > val.Time+uint64(aliveCnt*time.Second) {
			continue
		}
		// cpu rate is ok and we did pause for aliveCnt seconds
		if val.Rate < r.opts.Events && last > val.Throttled+uint64(aliveCnt*time.Second) {
			continue
		}
		stop = false
	}

	if stop {
		// We do race with ebpf cgroup_rate code in here. But in case
		// there's enough events to cross the limit, the cgroup will get
		// throttled with the next event and in opposite case where the
		// rate does not cross the limit we do nothing.
		for idx := range values {
			// pending throttle stop
			values[idx].Throttled = 0
		}
		if err := hash.Put(key, values); err != nil {
			cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.UpdateFail)
		}
		// stop throttle event
		r.notify(&tracing.MsgProcessThrottleUnix{
			Type:   tetragon.ThrottleType_THROTTLE_STOP,
			Cgroup: cgroup,
			Ktime:  last,
		})
		cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.ThrottleStop)
		return true
	}

	return false
}

// Called from event handlers to kick off the cgroup rate
// periodical check for event's cgroup.
func Check(kube *processapi.MsgK8s, ktime uint64) {
	if glSt.handle == nil {
		return
	}

	glSt.mu.RLock()
	defer glSt.mu.RUnlock()

	if glSt.handle == nil {
		return
	}

	cq := &cgroupQueue{
		id:    kube.Cgrpid,
		ktime: ktime,
		name:  string(kube.Docker[:]),
	}

	glSt.handle.ch <- cq
	cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.Check)
}

func Config() {
	if glSt.handle == nil {
		return
	}

	if glSt.cgRateOptionsMap.MapHandle == nil {
		glSt.handle.log.Warn("failed to update cgroup rate options map")
		return
	}

	key := uint32(0)
	opts := processapi.CgroupRateOptions{
		Events:   glSt.handle.opts.Events,
		Interval: glSt.handle.opts.Interval,
	}

	if err := glSt.cgRateOptionsMap.MapHandle.Put(key, opts); err != nil {
		cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.UpdateFail)
	}
}

func RegisterCgroupRate(sensor *sensors.Sensor) (*sensors.Sensor, error) {
	if !option.CgroupRateEnabled() {
		return sensor, nil
	}

	glSt.mu.Lock()
	defer glSt.mu.Unlock()

	if glSt.handle != nil {
		return nil, errors.New("cgrouprate: handle is already set, need to cleanup first")
	}

	var rateProgs []*program.Program
	var optsProgs []*program.Program
	for _, p := range sensor.Progs {
		if base.IsExecve(p) || base.IsFork(p) || base.IsExit(p) {
			rateProgs = append(rateProgs, p)
		}
		if base.IsExecve(p) {
			optsProgs = append(optsProgs, p)
		}
	}

	if len(optsProgs) == 0 || len(rateProgs) == 0 {
		return nil, errors.New("failed to find base programs")
	}

	cgRmdirProg := program.Builder(
		"bpf_cgroup.o",
		"cgroup/cgroup_rmdir",
		"raw_tracepoint/cgroup_rmdir",
		"tg_cgroup_rmdir",
		"raw_tracepoint",
	).SetPolicy(optsProgs[0].Policy)
	rateProgs = append(rateProgs, cgRmdirProg)

	glSt.cgRateMap = program.MapBuilder("cgroup_rate_map", rateProgs...)
	glSt.cgRateMap.SetMaxEntries(cgRateMaxEntries)
	glSt.cgRateOptionsMap = program.MapBuilder("cgroup_rate_options_map", optsProgs...)

	sensor.Progs = append(sensor.Progs, cgRmdirProg)
	sensor.Maps = append(sensor.Maps, glSt.cgRateMap, glSt.cgRateOptionsMap)
	return sensor, nil
}

func init() {
	base.RegisterExtensionAtInit("cgroup_rate", RegisterCgroupRate)
}
