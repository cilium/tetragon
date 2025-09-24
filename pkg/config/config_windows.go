// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

// ExecObj returns the exec object based on the kernel version
func ExecObj() string {
	return ""
}

func ExitObj() string {
	return ""
}

func ExecUpdateObj() string {
	return ""
}

func ForkObj() string {
	return ""
}

func BprmCommitObj() string {
	return ""
}

func EnforcerObj() string {
	return ""
}

func MultiEnforcerObj() string {
	return ""
}

func FmodRetEnforcerObj() string {
	return ""
}

func LoaderObj() string {
	return ""
}

func CgroupObj() string {
	return ""
}

func CgtrackerObj() string {
	return ""
}

// GenericKprobeObjs returns the generic kprobe and generic retprobe objects
func GenericKprobeObjs(_ bool) (string, string) {
	return "", ""
}

func GenericUprobeObjs(_ bool) string {
	return ""
}

func GenericTracepointObjs(_ bool) string {
	return ""
}

func GenericLsmObjs() (string, string) {
	return "", ""
}

func EnableRhel7Progs() bool {
	return false
}

func EnableV513Progs() bool {
	return false
}

func EnableV61Progs() bool {
	return false
}

func EnableV612Progs() bool {
	return false
}

func EnableLargeProgs() bool {
	return false
}
