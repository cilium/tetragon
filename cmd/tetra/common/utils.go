// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// HumanizeByteCount transforms bytes count into a quickly-readable version, for
// example it transforms 4458824 into "4.46 MB". I copied this code from
// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
func HumanizeByteCount(b int) string {
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
	// tabwriter config imitates kubectl default output, i.e. 3 spaces padding
	w := tabwriter.NewWriter(output, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSTATE\tFILTERID\tNAMESPACE\tSENSORS\tKERNELMEMORY\tMODE")

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

		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t\n",
			pol.Id,
			pol.Name,
			strings.TrimPrefix(strings.ToLower(pol.State.String()), "tp_state_"),
			pol.FilterId,
			namespace,
			sensors,
			HumanizeByteCount(int(pol.KernelMemoryBytes)),
			strings.TrimPrefix(strings.ToLower(pol.Mode.String()), "tp_mode_"),
		)
	}
	w.Flush()
}
