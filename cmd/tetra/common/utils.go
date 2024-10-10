// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import "fmt"

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
