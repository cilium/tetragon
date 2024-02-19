// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Isovalent Inc.

package metricsmd

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Generate
func Generate(reg *prometheus.Registry, w io.Writer, labelOverrides []LabelOverrides) error {
	metricsFamilies, err := reg.Gather()
	if err != nil {
		return err
	}
	sort.Slice(metricsFamilies, func(i, j int) bool {
		return metricsFamilies[i].GetName() < metricsFamilies[j].GetName()
	})

	for _, metric := range metricsFamilies {
		// Include the metric name and help text.
		io.WriteString(w, fmt.Sprintf("## `%s`\n\n", metric.GetName()))
		io.WriteString(w, fmt.Sprintf("%s\n\n", metric.GetHelp()))
		// The rest is generating a list of label names and values

		// map of "label_name" -> set([label_values...])
		labelsToValues := make(map[string]map[string]struct{})

		// Iterate over the series
		series := metric.GetMetric()
		for _, m := range series {
			for _, label := range m.GetLabel() {
				// Check if the map entry exists
				_, ok := labelsToValues[label.GetName()]
				if !ok {
					// Initialize it
					labelsToValues[label.GetName()] = make(map[string]struct{})
				}
				// Add the value to the set of values for this label
				labelsToValues[label.GetName()][label.GetValue()] = struct{}{}
			}
		}

		// Support overriding the values of labels, in case they're not suitable for docs.
		for _, override := range labelOverrides {
			if override.Metric != metric.GetName() {
				continue
			}
			for _, o := range override.Overrides {
				// Erase the current labels if any exist
				labelsToValues[o.Label] = make(map[string]struct{})
				for _, overrideVal := range o.Values {
					labelsToValues[o.Label][overrideVal] = struct{}{}
				}
			}
		}

		// Generate a list of labels and their values
		var finalLabels []LabelValues
		for label, valuesMap := range labelsToValues {
			var vals []string
			for val := range valuesMap {
				vals = append(vals, val)
			}
			// Sort the values
			sort.Strings(vals)
			finalLabels = append(finalLabels, LabelValues{
				Label:  label,
				Values: vals,
			})
		}

		// Write out the labels out if there are any
		if len(finalLabels) > 0 {
			sort.Slice(finalLabels, func(i, j int) bool {
				return finalLabels[i].Label < finalLabels[j].Label
			})
			io.WriteString(w, "| label | values |\n")
			io.WriteString(w, "| ----- | ------ |\n")
			for _, labelVal := range finalLabels {
				row := fmt.Sprintf("| `%-5s` | `%5s` |\n", labelVal.Label, strings.Join(labelVal.Values, ", "))
				io.WriteString(w, row)
			}
			io.WriteString(w, "\n")
		}
	}
	return nil
}

type LabelValues struct {
	Label  string
	Values []string
}

type LabelOverrides struct {
	Metric    string
	Overrides []LabelValues
}
