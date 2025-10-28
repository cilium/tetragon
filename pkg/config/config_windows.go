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

// GenericKprobeObjs returns the generic kprobe and generic retprobe objects
func GenericKprobeObjs(_ bool) (string, string) {
	return "", ""
}

func GenericUprobeObjs(_ bool) (string, string) {
	return "", ""
}

func GenericTracepointObjs(_ bool) string {
	return ""
}

func GenericLsmObjs() (string, string) {
	return "", ""
}

func CGroupMkdirObj() string {
	return ""
}

func CGroupReleaseObj() string {
	return ""
}

func CGroupRmdirObj() string {
	return ""
}

func LoaderObj() string {
	return ""
}

func EnableRhel7Progs() bool {
	return false
}

func EnableV511Progs() bool {
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

func GetRBSize() int {
	return 0
}
