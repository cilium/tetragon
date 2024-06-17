// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// initializer contains methods for metrics initialization and checking
// constraints.
type initializer interface {
	IsConstrained() bool
	Init()
	InitForDocs()
}

// CollectorWithInit extends prometheus.Collector with initializer.
type CollectorWithInit interface {
	prometheus.Collector
	initializer
}

// Group extends prometheus.Registerer with CollectorWithInit.
// It represents a sub-registry of the root prometheus.Registry.
type Group interface {
	prometheus.Registerer
	CollectorWithInit
	ExtendInit(func())
	ExtendInitForDocs(func())
}

// metricsGroup wraps prometheus.Registry and implements Group
type metricsGroup struct {
	registry *prometheus.Registry
	// If constrained is true, group will accept collectors implementing
	// initializer only if they are constrained.
	constrained     bool
	initFunc        func()
	initForDocsFunc func()
}

// NewMetricsGroup creates a new Group.
func NewMetricsGroup(constrained bool) Group {
	return &metricsGroup{
		registry:        prometheus.NewPedanticRegistry(),
		constrained:     constrained,
		initFunc:        func() {},
		initForDocsFunc: func() {},
	}
}

// Describe implements Group (prometheus.Collector).
func (r *metricsGroup) Describe(ch chan<- *prometheus.Desc) {
	r.registry.Describe(ch)
}

// Collect implements Group (prometheus.Collector).
func (r *metricsGroup) Collect(ch chan<- prometheus.Metric) {
	r.registry.Collect(ch)
}

// Register implements Group (prometheus.Registerer).
//
// It wraps the Register method of the underlying registry. Additionally, if
// the collector implements initializer, it:
//   - checks constraints - attempt to register an unconstrained collector in
//     a constrained group results in an error
//   - extends Init and InitForDocs methods with initialization of the
//     registered collector
func (r *metricsGroup) Register(c prometheus.Collector) error {
	cc, hasInit := c.(initializer)
	if hasInit {
		// check constraints
		if r.IsConstrained() && !cc.IsConstrained() {
			return errors.New("can't register unconstrained metrics in a constrained group")
		}
	}
	// register
	err := r.registry.Register(c)
	if err != nil {
		return err
	}
	if hasInit {
		// extend init
		r.ExtendInit(cc.Init)
		r.ExtendInitForDocs(cc.InitForDocs)
	}
	return nil
}

// MustRegister implements Group (prometheus.Registerer).
func (r *metricsGroup) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}

// Unregister implements Group (prometheus.Registerer).
func (r *metricsGroup) Unregister(c prometheus.Collector) bool {
	return r.registry.Unregister(c)
}

// IsConstrained implements Group (initializer).
func (r *metricsGroup) IsConstrained() bool {
	return r.constrained
}

// Init implements Group (initializer).
func (r *metricsGroup) Init() {
	if r.initFunc != nil {
		r.initFunc()
	}
}

// InitForDocs implements Group (initializer).
func (r *metricsGroup) InitForDocs() {
	if r.initForDocsFunc != nil {
		r.initForDocsFunc()
	}
}

// ExtendInit extends the metricsGroup Init and InitForDocs methods.
//
// For metrics implementing CollectorWithInit, initialization function should
// be passed when defining the metric, so this method shouldn't be called
// explicitly. However, when adding existing metrics (not implementing
// CollectorWithInit) into a metrics group, it's helpful to extend the group's
// initialization function separately.
func (r *metricsGroup) ExtendInit(init func()) {
	if init != nil {
		if r.initFunc == nil {
			r.initFunc = init
		} else {
			oldInit := r.initFunc
			r.initFunc = func() {
				oldInit()
				init()
			}
		}
	}
	r.ExtendInitForDocs(init)
}

// ExtendInit extends the metricsGroup InitForDocs method.
//
// See ExtendInit for usage notes.
func (r *metricsGroup) ExtendInitForDocs(init func()) {
	if init != nil {
		if r.initForDocsFunc == nil {
			r.initForDocsFunc = init
		} else {
			oldInit := r.initForDocsFunc
			r.initForDocsFunc = func() {
				oldInit()
				init()
			}
		}
	}
}
