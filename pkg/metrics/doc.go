// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// The metrics package provides a set of helpers (wrappers around
// [prometheus Go library](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus))
// for defining and managing prometheus metrics.
//
// The package is designed to support the following functionality:
//   - Group metrics based on their purpose and load groups independently.
//     This gives us more control over what metrics are exposed and how
//     cardinality is managed.
//   - Define custom collectors, e.g. reading metrics directly from BPF maps.
//     This decouples metrics from events passed through ringbuffer.
//   - Let users configure high-cardinality dynamic labels, for both "regular"
//     metrics and custom collectors.
//   - Constrain metrics cardinality for metrics with known labels.
//   - Initialize metrics with known labels on startup.
//     This makes resources usage more predictable, as cardinality of these
//     metrics won't grow.
//   - Autogenerate reference documentation from metrics help texts.
//   - Delete stale metrics. This will prevent growing cardinality.
//     Currently we do it when a pod is deleted, but it should be easy to
//     extend this to other cases.
//   - Keep common labels consistent between metrics.
//     This makes it easier to write queries.
//
// Here we describe the key parts of the metrics package. See also doc comments
// in the code for more details.
//
// `Group` interface and `metricsGroup` struct implementing it are
// wrappers around `prometheus.Registry` intended to define sub-registries of
// the root registry. In addition to registering metrics, it supports:
//   - initializing metrics on startup
//   - initializing metrics for generating docs
//   - constraining metrics cardinality (constrained group contains only
//     metrics with constrained cardinality)
//
// `Opts` struct is a wrapper around `prometheus.Opts` that additionally
// supports defining constrained and unconstrained labels.
//
// `ConstrainedLabel` and `UnconstrainedLabel` structs represent metric labels.
//
// `FilteredLabels` interface represents configurable labels. It's intended to
// be used as a type parameter when defining a granular metric, to add common
// labels. The idea is that users can configure which of these (potentially
// high-cardinality) labels are actually exposed - see `CreateProcessLabels` in
// `pkg/option` for an example. The values of these labels are always
// unconstrained. `NilLabels` package variable is a special case of
// `FilteredLabels` with no labels, which is used in convenience wrappers
// around granular metrics.
//
// `GranularCounter[L FilteredLabels]` (and analogous Gauge and Histogram)
// struct is a wrapper around `prometheus.CounterVec` (Gauge, Histogram) with
// additional properties:
//   - cardinality can be constrained
//   - support for configurable labels
//   - metric is initialized at startup for known label values
//   - metric is automatically included in generated docs
//
// `Counter` (and analogous Gauge and Histogram) struct is a convenience
// wrapper around `GranularCounter[NilLabels]` (Gauge, Histogram).
//
// `customCollector` struct represents a custom collector (e.g. reading metrics
// directly from a BPF map). It contains a list of metrics, collect function
// and an optional separate collect function for generating docs.
//
// `GranularCustomMetric[L FilteredLabels]` interface and
// `granularCustomCounter` struct (and analogous Gauge) implementing it
// represent a metric that's not stored and updated using prometheus library,
// but collected independently, e.g. directly from a BPF map. Similarly like
// "regular" metrics, it supports constraining cardinality and adding
// configurable labels via type parameter.
//
// `CustomMetric` interface and `customCounter` struct (and analogous Gauge)
// implementing it are convenience wrappers around
// `GranularCustomMetric[NilLabels]`.
package metrics
