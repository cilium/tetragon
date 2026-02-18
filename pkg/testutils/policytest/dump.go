// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"fmt"
	"io"
	"text/tabwriter"
)

func DumpResults(out io.Writer, ptNames []string, results []*Result) {
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for i, res := range results {
		ptName := ptNames[i]
		var note string
		var icon string
		if res.Err != nil {
			icon = "❌"
			note = res.Err.Error()
		} else if res.Skipped != "" {
			icon = "⏭️"
			note = res.Skipped
		} else {
			nScenarios := len(res.ScenariosRes)
			nSuccesses := 0
			for _, sc := range res.ScenariosRes {
				if sc.Err() == nil {
					nSuccesses++
				}
			}
			switch nSuccesses {
			case nScenarios:
				icon = "✅"
			case 0:
				icon = "🔴"
			default:
				icon = "🟠"
			}
			note = fmt.Sprintf("%d/%d scenario(s) succeeded", nSuccesses, nScenarios)
		}
		fmt.Fprintf(w, "P: %s\t%s\t%s\n", ptName, icon, note)
		for i, sc := range res.ScenariosRes {
			scIcon := "🟢"
			scNote := ""
			if err := sc.Err(); err != nil {
				scNote = err.Error()
				scIcon = "🔴"
			}
			prefix := "├"
			if i == len(res.ScenariosRes)-1 {
				prefix = "└"
			}
			fmt.Fprintf(w, "%sS: %s\t%s\t%s\n", prefix, sc.Name, scIcon, scNote)
		}
	}
	w.Flush()
}
