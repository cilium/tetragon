// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kernels

import (
	"strconv"
	"strings"
)

func KernelStringToNumeric(ver string) int64 {
	// vendors like to define kernel 4.14.128-foo but
	// everything after '-' is meaningless from BPF
	// side so toss it out.
	release := strings.Split(ver, "-")
	verStr := release[0]
	numeric := strings.TrimRight(verStr, "+")
	vers := strings.Split(numeric, ".")

	// Split out major, minor, and patch versions
	majorS := vers[0]
	minorS := ""
	if len(vers) >= 2 {
		minorS = vers[1]
	}
	patchS := ""
	if len(vers) >= 3 {
		patchS = vers[2]
	}

	// If we have no major version number, all is lost
	major, err := strconv.ParseInt(majorS, 10, 32)
	if err != nil {
		return 0
	}
	// Fall back to minor = 0 if we can't parse the minor version
	minor, err := strconv.ParseInt(minorS, 10, 32)
	if err != nil {
		minor = 0
	}
	// Fall back to patch = 0 if we can't parse the patch version
	patch, err := strconv.ParseInt(patchS, 10, 32)
	if err != nil {
		patch = 0
	}
	// Similar to https://elixir.bootlin.com/linux/v6.2.16/source/tools/lib/bpf/bpf_helpers.h#L74
	// we have to check that patch is <= 255. Otherwise make that 255.
	if patch > 255 {
		patch = 255
	}

	return ((major << 16) + (minor << 8) + patch)
}
