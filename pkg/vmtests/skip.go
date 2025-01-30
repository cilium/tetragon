// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package vmtests

import (
	"regexp"
)

type skipRule struct {
	TestNameRe string
	testNameRe *regexp.Regexp

	KernelRe string
	kernelRe *regexp.Regexp
}

// We should probably have this in a json file, but for now we keep it here
var rules = []skipRule{
	skipRule{TestNameRe: "pkg.sensors.tracing.TestLoader", KernelRe: "(6\\.6|6\\.1)"},
	skipRule{TestNameRe: "pkg.tracepoint.TestTracepointLoadFormat", KernelRe: "(6\\.1|bpf-next)"},
	skipRule{TestNameRe: "pkg.sensors.exec.TestProcessCacheInterval", KernelRe: ""},
	skipRule{TestNameRe: "pkg.watcher.TestFastK8s", KernelRe: ""},
}

func init() {
	for i := range rules {
		r := &rules[i]
		r.testNameRe = regexp.MustCompile(r.TestNameRe)
		r.kernelRe = regexp.MustCompile(r.KernelRe)
	}
}

func shouldSkip(cnf *Conf, testName string) bool {
	for i := range rules {
		r := &rules[i]
		if r.kernelRe.MatchString(cnf.KernelVer) && r.testNameRe.MatchString(testName) {
			return true
		}
	}

	return false
}
