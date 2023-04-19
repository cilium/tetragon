// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"regexp"
	"strconv"
)

type ThreadTesterInfo struct {
	ParentPid, ParentTid                     uint32
	Child1Pid, Child1Tid, ParentChild1Pid    uint32
	Thread1Pid, Thread1Tid, ParentThread1Pid uint32
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
			tti.ParentPid = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			tti.ParentTid = uint32(v)
		}
	} else if match := Child1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			tti.Child1Pid = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			tti.Child1Tid = uint32(v)
		}
		v, err = strconv.ParseUint(match[3], 10, 32)
		if err == nil {
			tti.ParentChild1Pid = uint32(v)
		}
	} else if match := Thread1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			tti.Thread1Pid = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			tti.Thread1Tid = uint32(v)
		}
		v, err = strconv.ParseUint(match[3], 10, 32)
		if err == nil {
			tti.ParentThread1Pid = uint32(v)
		}
	}
	return err
}
