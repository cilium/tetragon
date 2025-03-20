// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

// ExecObj returns the exec object based on the kernel version
func ExecObj() string {
	return ""
}

// GenericKprobeObjs returns the generic kprobe and generic retprobe objects
func GenericKprobeObjs() (string, string) {
	return "", ""
}

func EnableV61Progs() bool {
	return false
}

func EnableLargeProgs() bool {
	return false
}
