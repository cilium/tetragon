// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouprate

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/cgroupratemetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
)

var (
	handle     *CgroupRate
	handleLock sync.RWMutex
)

type Listener interface {
	Notify(msg notify.Message) error
	io.Closer
}

type cgroupRate struct {
	key  processapi.CgroupRateKey
	name string
}

type CgroupRate struct {
	listeners map[Listener]struct{}
	log       logrus.FieldLogger
	ch        chan *cgroupRate
	flag      map[processapi.CgroupRateKey]bool
	flagLock  sync.Mutex
	rates     []*cgroupRate
	opts      *option.CgroupRate
	hash      *program.Map
}

func NewCgroupRate(ctx context.Context,
	hash *program.Map,
	opts *option.CgroupRate) *CgroupRate {

	if opts.Events == 0 || opts.Interval == 0 {
		logger.GetLogger().Infof("Cgroup rate disabled (opts %d/%d)",
			opts.Events, opts.Interval)
		return nil
	}

	handleLock.Lock()
	defer handleLock.Unlock()

	handle = &CgroupRate{
		listeners: make(map[Listener]struct{}),
		log:       logger.GetLogger(),
		flag:      make(map[processapi.CgroupRateKey]bool),
		ch:        make(chan *cgroupRate),
		hash:      hash,
		opts:      opts,
	}

	go handle.process(ctx)
	return handle
}

func (r *CgroupRate) AddListener(listener Listener) {
	r.listeners[listener] = struct{}{}
}

func (r *CgroupRate) RemoveListener(listener Listener) {
	delete(r.listeners, listener)
	if err := listener.Close(); err != nil {
		r.log.WithError(err).Warn("failed to close listener")
	}
}

func (r *CgroupRate) Notify(msg notify.Message) {
	for listener := range r.listeners {
		if err := listener.Notify(msg); err != nil {
			r.log.WithError(err).Warn("failed to notify listener")
			r.RemoveListener(listener)
		}
	}
}

func (r *CgroupRate) process(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	r.log.Info("Cgroup rate started (500ms timer)")

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case rate := <-r.ch:
			r.rates = append(r.rates, rate)
		case <-ticker.C:
			r.checkRates()
		}
	}
}

func (r *CgroupRate) checkRates() {
	last, err := ktime.Monotonic()
	if err != nil {
		return
	}

	var tmp []*cgroupRate

	for _, rate := range r.rates {
		if r.checkRate(rate, uint64(last)) {
			tmp = append(tmp, rate)
		}
	}
	r.rates = tmp
}

func (r *CgroupRate) checkRate(rate *cgroupRate, last uint64) bool {
	cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.CheckRate)

	values := make([]processapi.CgroupRateValue, bpf.GetNumPossibleCPUs())

	if r.hash.MapHandle == nil {
		return true
	}

	hash := r.hash.MapHandle

	if err := hash.Lookup(rate.key, &values); err != nil {
		cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.LookupFail)
		return false
	}

	compute := func(v *processapi.CgroupRateValue) uint64 {
		if last > v.Time+uint64(r.opts.Interval) {
			return 0
		}
		slide := r.opts.Interval - (last - v.Time)
		partial := float64(slide) / float64(r.opts.Interval)
		return uint64(float64(v.Prev)*partial) + v.Curr
	}

	var (
		events      uint64
		isThrottled bool
	)

	for _, val := range values {
		events = events + compute(&val)
		isThrottled = isThrottled || val.Throttle != 0
	}

	setThrottle := func(throttle uint64) {
		for idx := range values {
			values[idx].Throttle = throttle
		}
		if err := hash.Update(rate.key, values, 0); err != nil {
			cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.UpdateFail)
		}
	}

	isAlive := func() bool {
		if events == 0 {
			r.delFlag(rate.key)
			if err := hash.Delete(rate.key); err != nil {
				cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.DeleteFail)
			}
			return false
		}
		return true
	}

	if !isThrottled && events >= r.opts.Events {
		setThrottle(1)
		r.Notify(&tracing.MsgProcessThrottleUnix{
			Type:   tetragon.ThrottleType_THROTTLE_START,
			Cgroup: fmt.Sprintf("%s-%d", rate.name, rate.key.Id),
		})
		cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.ThrottleStart)
		return true
	}

	if isThrottled && events < r.opts.Events {
		setThrottle(0)
		r.Notify(&tracing.MsgProcessThrottleUnix{
			Type:   tetragon.ThrottleType_THROTTLE_STOP,
			Cgroup: fmt.Sprintf("%s-%d", rate.name, rate.key.Id),
		})
		cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.ThrottleStop)
		return isAlive()
	}

	return isAlive()
}

func (r *CgroupRate) addFlag(key processapi.CgroupRateKey) bool {
	r.flagLock.Lock()
	defer r.flagLock.Unlock()

	var ok bool
	if _, ok = r.flag[key]; !ok {
		r.flag[key] = true
		cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.FlagAdd)
	}
	return ok
}

func (r *CgroupRate) delFlag(key processapi.CgroupRateKey) {
	r.flagLock.Lock()
	defer r.flagLock.Unlock()

	delete(r.flag, key)
	cgroupratemetrics.CgroupRateTotalInc(cgroupratemetrics.FlagDel)
}

func Check(kube *processapi.MsgK8s) {
	if handle == nil {
		return
	}

	key := processapi.CgroupRateKey{
		Id: kube.Cgrpid,
	}

	handleLock.RLock()
	defer handleLock.RUnlock()

	if handle == nil || handle.addFlag(key) {
		return
	}

	rate := &cgroupRate{
		key:  key,
		name: string(kube.Docker[:]),
	}

	handle.ch <- rate
}

func Config(optsMap *program.Map) {
	if handle == nil {
		return
	}

	if optsMap.MapHandle == nil {
		handle.log.Warn("failed to update cgroup rate options map")
		return
	}

	key := uint32(0)
	opts := processapi.CgroupRateOptions{
		Interval: handle.opts.Interval,
	}

	if err := optsMap.MapHandle.Put(key, opts); err != nil {
		handle.log.WithError(err).Warn("failed to update cgroup rate options map")
	}
}
