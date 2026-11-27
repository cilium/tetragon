// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ldso

import "debug/elf"

// archHwcaps returns no glibc-hwcaps subdirectories: glibc defines none for
// arm64.
func archHwcaps(_ elf.Machine, _ elf.Class) []string {
	return nil
}
