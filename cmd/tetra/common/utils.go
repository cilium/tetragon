// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// HumanizeByteCount transforms bytes count into a quickly-readable version, for
// example it transforms 4458824 into "4.46 MB". I copied this code from
// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
func HumanizeByteCount(b uint64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func PrintTracingPolicies(output io.Writer, policies []*tetragon.TracingPolicyStatus, skipPolicy func(pol *tetragon.TracingPolicyStatus) bool) {
	// Render the summary table on its own tabwriter first, so its column
	// widths aren't skewed by the (unrelated) per-hook status columns.
	// hookStatusByRow remembers, for each rendered summary row (0 is the
	// header), the hook statuses that should be interleaved right below it.
	var mainBuf bytes.Buffer
	hookStatusByRow := map[int][]*tetragon.HookStatus{}

	// tabwriter config imitates kubectl default output, i.e. 3 spaces padding
	w := tabwriter.NewWriter(&mainBuf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tDOMAIN\tSTATE\tFILTERID\tNAMESPACE\tSENSORS\tKERNELMEMORY\tMODE\tNPOST\tNENFORCE\tNMONITOR")

	row := 0
	for _, pol := range policies {
		if skipPolicy != nil && skipPolicy(pol) {
			continue
		}

		namespace := pol.Namespace
		if namespace == "" {
			namespace = "(global)"
		}

		sensors := strings.Join(pol.Sensors, ",")

		// From v0.11 and before, enabled, filterID and error were
		// bundled in a string. To have a retro-compatible tetra
		// command, we scan the string. If the scan fails, it means
		// something else might be in Info and we print it.
		//
		// we can drop the following block (and comment) when we
		// feel tetra should support only version after v0.11
		if pol.Info != "" {
			var parsedEnabled bool
			var parsedFilterID uint64
			var parsedError string
			var parsedName string
			str := strings.NewReader(pol.Info)
			_, err := fmt.Fscanf(str, "%253s enabled:%t filterID:%d error:%512s", &parsedName, &parsedEnabled, &parsedFilterID, &parsedError)
			if err == nil {
				if parsedEnabled {
					pol.State = tetragon.TracingPolicyState_TP_STATE_ENABLED
				}
				pol.FilterId = parsedFilterID
				pol.Error = parsedError
				pol.Info = ""
			}
		}

		counters := pol.GetStats().GetActionCounters()
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
			pol.Id,
			pol.Name,
			pol.Domain,
			strings.TrimPrefix(strings.ToLower(pol.State.String()), "tp_state_"),
			pol.FilterId,
			namespace,
			sensors,
			HumanizeByteCount(pol.KernelMemoryBytes),
			strings.TrimPrefix(strings.ToLower(pol.Mode.String()), "tp_mode_"),
			counters.GetPost(),
			counters.GetSignal()+counters.GetOverride()+counters.GetNotifyEnforcer()+counters.GetSet(),
			counters.GetMonitorSignal()+counters.GetMonitorOverride()+counters.GetMonitorNotifyEnforcer()+counters.GetMonitorSet())
		row++

		// When a policy is only partially loaded, interleave its
		// per-hook status right below its summary row so it's
		// clear which hooks failed to load.
		if pol.State == tetragon.TracingPolicyState_TP_STATE_PARTIALLY_ENABLED && len(pol.HookStatuses) > 0 {
			hookStatusByRow[row] = pol.HookStatuses
		}
	}
	w.Flush()

	lines := strings.Split(strings.TrimSuffix(mainBuf.String(), "\n"), "\n")

	// Column 2 (NAME) starts right after the padded ID column; measure it
	// from the rendered header so hook-status sub-tables can be indented
	// to line up underneath it, without affecting the summary table's own
	// column widths.
	indent := strings.Repeat(" ", strings.Index(lines[0], "NAME"))

	for i, line := range lines {
		fmt.Fprintln(output, line)
		if hookStatuses, ok := hookStatusByRow[i]; ok {
			fmt.Fprint(output, renderHookStatuses(hookStatuses, indent))
		}
	}
}

func renderHookStatuses(hookStatuses []*tetragon.HookStatus, indent string) string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SECTION\tCFGIDX\tDESCRIPTION\tSTATUS")
	for _, hs := range hookStatuses {
		state := strings.TrimPrefix(strings.ToLower(hs.State.String()), "status_")
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", hs.Section, hs.HookIdx, hs.HookDescription, state)
	}
	w.Flush()

	var out strings.Builder
	for line := range strings.SplitSeq(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		out.WriteString(indent)
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.String()
}
