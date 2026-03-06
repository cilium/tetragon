// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

func checkFentry(t *testing.T) {
	if !config.EnableV61Progs() {
		t.Skip("fentry requires at least 6.1 kernel")
	}
}

func TestFentryObjectLoad(t *testing.T) {
	checkFentry(t)
	testKprobeObjectLoad(t, true)
}

func TestFentryLseek(t *testing.T) {
	checkFentry(t)
	policytest.AllPolicyTests.DoObserverTest(t, "kprobe-lseek", map[string]any{
		"Hook": "fentries",
	})
}

func TestFentryObjectWriteReadHostNs(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteReadHostNs(t, true)
}

func TestFentryObjectWriteRead(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteRead(t, true)
}

func TestFentryObjectWriteCapsNotIn(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteCapsNotIn(t, true)
}

func TestFentryObjectWriteReadNsOnly(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteReadNsOnly(t, true)
}

func TestFentryObjectWriteReadPidOnly(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteReadPidOnly(t, true)
}

func TestFentryObjectRead(t *testing.T) {
	checkFentry(t)
	testKprobeObjectRead(t, true)
}

func TestFentryObjectReadIdxMismatch(t *testing.T) {
	checkFentry(t)
	testKprobeObjectReadIdxMismatch(t, true)
}

func TestFentryObjectReadReturn(t *testing.T) {
	checkFentry(t)
	testKprobeObjectReadReturn(t, true)
}

func TestFentryObjectReturnCopy(t *testing.T) {
	checkFentry(t)
	testKprobeObjectReturnCopy(t, true)
}
