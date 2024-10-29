// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	LabelPolicyNamespace = UnconstrainedLabel{Name: "policy_namespace", ExampleValue: "ns"}
	LabelPolicy          = UnconstrainedLabel{Name: "policy", ExampleValue: "enforce"}
)

// ConstrainedLabel represents a label with constrained cardinality.
// Values is a list of all possible values of the label.
type ConstrainedLabel struct {
	Name   string
	Values []string
}

// UnconstrainedLabel represents a label with unconstrained cardinality.
// ExampleValue is an example value of the label used for documentation.
type UnconstrainedLabel struct {
	Name         string
	ExampleValue string
}

func stringToUnconstrained(labels []string) []UnconstrainedLabel {
	unconstrained := make([]UnconstrainedLabel, len(labels))
	for i, label := range labels {
		unconstrained[i] = UnconstrainedLabel{
			Name:         label,
			ExampleValue: "example",
		}
	}
	return unconstrained
}

func promContainsLabel(labels prometheus.ConstrainedLabels, label string) bool {
	for _, l := range labels {
		if l.Name == label {
			return true
		}
	}
	return false
}

var (
	// TODO: Standardize labels used by different metrics: op, msg_op, opcode.
	// Also, add a human-readable counterpart.
	OpCodeLabel = ConstrainedLabel{
		Name: "msg_op",
		// These are numbers, not human-readable names.
		Values: getOpcodes(),
	}
	EventTypeLabel = ConstrainedLabel{
		Name:   "event_type",
		Values: getEventTypes(),
	}
)

func getOpcodes() []string {
	result := make([]string, len(ops.OpCodeStrings)-2)
	i := 0
	for opcode := range ops.OpCodeStrings {
		if opcode != ops.MSG_OP_UNDEF && opcode != ops.MSG_OP_TEST {
			result[i] = fmt.Sprint(int32(opcode))
			i++
		}
	}
	return result
}

func getEventTypes() []string {
	result := make([]string, len(tetragon.EventType_name)-2)
	i := 0
	for ev := range tetragon.EventType_name {
		eventType := tetragon.EventType(ev)
		if eventType != tetragon.EventType_UNDEF && eventType != tetragon.EventType_TEST {
			result[i] = eventType.String()
			i++
		}
	}
	return result
}
