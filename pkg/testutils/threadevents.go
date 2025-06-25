// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

type ThreadTesterInfo struct {
	ParentPID, ParentTid                     uint32
	Child1PID, Child1Tid, ParentChild1PID    uint32
	Thread1PID, Thread1Tid, ParentThread1PID uint32
}

var (
	ParentStartsRe = regexp.MustCompile(`parent:\t\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\tstarts`)
	Child1Re       = regexp.MustCompile(`Child 1:\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\t`)
	Thread1Re      = regexp.MustCompile(`Thread 1:\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\t`)
)

func (tti *ThreadTesterInfo) ParseLine(l string) error {
	var err error
	var v uint64
	if match := ParentStartsRe.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			tti.ParentPID = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			tti.ParentTid = uint32(v)
		}
	} else if match := Child1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			tti.Child1PID = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			tti.Child1Tid = uint32(v)
		}
		v, err = strconv.ParseUint(match[3], 10, 32)
		if err == nil {
			tti.ParentChild1PID = uint32(v)
		}
	} else if match := Thread1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			tti.Thread1PID = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			tti.Thread1Tid = uint32(v)
		}
		v, err = strconv.ParseUint(match[3], 10, 32)
		if err == nil {
			tti.ParentThread1PID = uint32(v)
		}
	}
	return err
}

func (tti *ThreadTesterInfo) AssertPidsTids(t *testing.T) {
	require.NotZero(t, tti.ParentPID)
	require.Equal(t, tti.ParentPID, tti.ParentTid)

	require.NotZero(t, tti.Child1PID)
	require.NotZero(t, tti.Child1Tid)
	require.Equal(t, tti.Child1PID, tti.Child1Tid)

	require.NotZero(t, tti.Thread1PID)
	require.NotZero(t, tti.Thread1Tid)
	require.NotEqual(t, tti.Thread1PID, tti.Thread1Tid)

	require.Equal(t, tti.Child1PID, tti.Thread1PID)
	require.Equal(t, tti.ParentChild1PID, tti.ParentPID)
	require.Equal(t, tti.ParentThread1PID, tti.ParentPID)
}
