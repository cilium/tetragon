// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

// ExecObj returns the exec object based on the kernel version
func ExecObj() string {
	return "process_monitor.sys"
}
