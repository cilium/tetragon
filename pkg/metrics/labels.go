// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"slices"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/ops"
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
	// OpCodeLabel holds the numeric value of an ops.OpCode. Pair it with
	// OpCodeNameLabel to also expose the human-readable opcode name.
	OpCodeLabel = ConstrainedLabel{
		Name: "opcode",
		// These are numbers, not human-readable names.
		Values: getOpcodes(false),
	}
	// OpCodeNameLabel is the human-readable counterpart of OpCodeLabel.
	OpCodeNameLabel = ConstrainedLabel{
		Name:   "opstr",
		Values: getOpcodeNames(false),
	}
	// OpCodeLabelWithUndef is OpCodeLabel extended with MSG_OP_UNDEF, for
	// metrics that report on unknown opcodes.
	OpCodeLabelWithUndef = ConstrainedLabel{
		Name:   "opcode",
		Values: getOpcodes(true),
	}
	// OpCodeNameLabelWithUndef is the human-readable counterpart of
	// OpCodeLabelWithUndef.
	OpCodeNameLabelWithUndef = ConstrainedLabel{
		Name:   "opstr",
		Values: getOpcodeNames(true),
	}
	EventTypeLabel = ConstrainedLabel{
		Name:   "event_type",
		Values: getEventTypes(),
	}
)

// sortedOpCodes returns the opcodes exposed as metric labels, in ascending
// order. MSG_OP_TEST is always excluded, as it's only used for testing.
// MSG_OP_UNDEF is included only if withUndef is set: it's not a valid
// operational opcode and is only used to report unknown opcodes.
//
// The order is deterministic so that getOpcodes and getOpcodeNames produce
// index-aligned slices, and so that generated documentation is stable.
func sortedOpCodes(withUndef bool) []ops.OpCode {
	result := make([]ops.OpCode, 0, len(ops.OpCodeStrings))
	for opcode := range ops.OpCodeStrings {
		if opcode == ops.MSG_OP_TEST {
			continue
		}
		if opcode == ops.MSG_OP_UNDEF && !withUndef {
			continue
		}
		result = append(result, opcode)
	}
	slices.Sort(result)
	return result
}

func getOpcodes(withUndef bool) []string {
	opcodes := sortedOpCodes(withUndef)
	result := make([]string, len(opcodes))
	for i, opcode := range opcodes {
		result[i] = strconv.Itoa(int(int32(opcode)))
	}
	return result
}

func getOpcodeNames(withUndef bool) []string {
	opcodes := sortedOpCodes(withUndef)
	result := make([]string, len(opcodes))
	for i, opcode := range opcodes {
		result[i] = opcode.String()
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
