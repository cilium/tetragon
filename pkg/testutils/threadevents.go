// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ThreadTesterInfo struct {
	parentParsed                             chan int
	childParsed                              chan int
	threadParsed                             chan int
	ParentPid, ParentTid                     uint32
	Child1Pid, Child1Tid, ParentChild1Pid    uint32
	Thread1Pid, Thread1Tid, ParentThread1Pid uint32
}

var (
	ParentStartsRe = regexp.MustCompile(`parent:\t\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\tstarts`)
	Child1Re       = regexp.MustCompile(`Child 1:\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\t`)
	Thread1Re      = regexp.MustCompile(`Thread 1:\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\t`)
)

func (tti *ThreadTesterInfo) InitChannels() {
	if tti.parentParsed == nil {
		tti.parentParsed = make(chan int)
	}
	if tti.childParsed == nil {
		tti.childParsed = make(chan int)
	}
	if tti.threadParsed == nil {
		tti.threadParsed = make(chan int)
	}
}

func (tti *ThreadTesterInfo) WaitForParentParsed(ctx context.Context) error {
	if tti.parentParsed == nil {
		return fmt.Errorf("wait for parent missing initialization")
	}
	timer := time.NewTimer(time.Second * 15)
	select {
	case <-timer.C:
		return fmt.Errorf("wait for parent output timedout")
	case <-ctx.Done():
		return ctx.Err()
	case <-tti.parentParsed:
		return nil
	}
}

func (tti *ThreadTesterInfo) WaitForChildParsed(ctx context.Context) error {
	if tti.childParsed == nil {
		return fmt.Errorf("wait for child missing initialization")
	}
	timer := time.NewTimer(time.Second * 15)
	select {
	case <-timer.C:
		return fmt.Errorf("wait for child output timedout")
	case <-ctx.Done():
		return ctx.Err()
	case <-tti.childParsed:
		return nil
	}
}

func (tti *ThreadTesterInfo) WaitForThreadParsed(ctx context.Context) error {
	if tti.threadParsed == nil {
		return fmt.Errorf("wait for thread missing initialization")
	}
	timer := time.NewTimer(time.Second * 15)
	select {
	case <-timer.C:
		return fmt.Errorf("wait for thread output timedout")
	case <-ctx.Done():
		return ctx.Err()
	case <-tti.threadParsed:
		return nil
	}
}

func (tti *ThreadTesterInfo) ParseLine(l string) error {
	var err error
	var v uint64

	if match := ParentStartsRe.FindStringSubmatch(l); len(match) > 0 {
		if tti.ParentPid == 0 || tti.ParentTid == 0 {
			v, err = strconv.ParseUint(match[1], 10, 32)
			if err == nil {
				tti.ParentPid = uint32(v)
			}
			v, err = strconv.ParseUint(match[2], 10, 32)
			if err == nil {
				tti.ParentTid = uint32(v)
			}
			if tti.ParentPid != 0 && tti.ParentTid != 0 && tti.parentParsed != nil {
				tti.parentParsed <- 1
			}
		}
	} else if match := Child1Re.FindStringSubmatch(l); len(match) > 0 {
		if tti.Child1Pid == 0 || tti.Child1Tid == 0 {
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
			if tti.Child1Pid != 0 && tti.Child1Tid != 0 && tti.childParsed != nil {
				tti.childParsed <- 1
			}
		}
	} else if match := Thread1Re.FindStringSubmatch(l); len(match) > 0 {
		if tti.Thread1Pid == 0 || tti.Thread1Tid == 0 {
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
			if tti.Thread1Pid != 0 && tti.Thread1Tid != 0 && tti.threadParsed != nil {
				tti.threadParsed <- 1
			}
		}
	}
	return err
}

func (tti *ThreadTesterInfo) AssertPidsTids(t *testing.T) {
	require.NotZero(t, tti.ParentPid)
	require.Equal(t, tti.ParentPid, tti.ParentTid)

	require.NotZero(t, tti.Child1Pid)
	require.NotZero(t, tti.Child1Tid)
	require.Equal(t, tti.Child1Pid, tti.Child1Tid)

	require.NotZero(t, tti.Thread1Pid)
	require.NotZero(t, tti.Thread1Tid)
	require.NotEqual(t, tti.Thread1Pid, tti.Thread1Tid)

	require.Equal(t, tti.Child1Pid, tti.Thread1Pid)
	require.Equal(t, tti.ParentChild1Pid, tti.ParentPid)
	require.Equal(t, tti.ParentThread1Pid, tti.ParentPid)
}
