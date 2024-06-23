// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/prometheus/client_golang/prometheus"
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

// TODO: Standardize labels used by different metrics: op, msg_op, opcode.
// Also, add a human-readable counterpart.
var OpCodeLabel = ConstrainedLabel{
	Name: "msg_op",
	// These are numbers, not human-readable names.
	Values: getOpcodes(),
}

func getOpcodes() []string {
	result := make([]string, len(ops.OpCodeStrings)-2)
	i := 0
	for opcode := range ops.OpCodeStrings {
		if opcode != ops.MsgOpUndef && opcode != ops.MsgOpTest {
			result[i] = fmt.Sprint(int32(opcode))
			i++
		}
	}
	return result
}
