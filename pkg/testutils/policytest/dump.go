// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"fmt"
	"io"
	"text/tabwriter"
)

type NamedResult struct {
	// Name is a policytest identifier
	Name string `json:"name"`
	// Results for the policytest
	Result *Result `json:"result"`
}

func DumpResults(out io.Writer, results []*NamedResult) {
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for _, result := range results {
		res := result.Result
		var note string
		var icon string
		if res.Err.Err != nil {
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
		fmt.Fprintf(w, "P: %-40s\t%s\t%s\n", result.Name, icon, note)
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

type ResultsSummary struct {
	Total   int
	Skipped int
	Errs    int
}

func NewResultsSummary() *ResultsSummary {
	return &ResultsSummary{}
}

func (s *ResultsSummary) Update(res *Result) {
	s.Total++
	if res.Err.Err != nil {
		s.Errs++
		return
	}
	if res.Skipped != "" {
		s.Skipped++
		return
	}

	for _, sr := range res.ScenariosRes {
		if sr.Err() != nil {
			s.Errs++
			return
		}
	}
}

func (s *ResultsSummary) Err() error {
	if s.Errs == 0 {
		return nil
	}
	return fmt.Errorf("result errors: %d/%d", s.Errs, s.Total)
}
