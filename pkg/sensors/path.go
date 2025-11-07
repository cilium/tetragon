// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"strings"
)

// something
// PathJoin creates a path meant for sensor filenames in /sys/fs/bpf.
//
// At some point, we would like to have a file hierarchy under /sys/fs/bpf for each sensor.
// see: https://github.com/cilium/tetragon/issues/408
//
// Unfortunately, this requires changes, for properly creating and deleting
// these directories requires. As an intermediate step, we use this function
// that uses dashes instead of / to create unique files in flat hierarchy,
// without needeing to manage directories.
func PathJoin(elem ...string) string {
	return strings.Join(elem, "-")
}
