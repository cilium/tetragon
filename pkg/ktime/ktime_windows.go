// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ktime

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	dll            = syscall.MustLoadDLL("kernel32.dll")
	queryCounter   = dll.MustFindProc("QueryPerformanceCounter")
	queryFrequency = dll.MustFindProc("QueryPerformanceFrequency")
)

func NanoTimeSince(ktime int64) (time.Duration, error) {
	nowTime := int64(time.Now().Nanosecond())
	diff := nowTime - ktime
	return time.Duration(diff), nil
}

func Monotonic() (time.Duration, error) {
	return time.Duration(time.Now().Nanosecond()), nil
}

func getBootTimeNanoseconds() int64 {
	var freq, counter int64
	queryFrequency.Call(uintptr(unsafe.Pointer(&freq)))
	queryCounter.Call(uintptr(unsafe.Pointer(&counter)))
	return (counter * 1e9) / freq
}

func DecodeKtime(ktime int64, monotonic bool) (time.Time, error) {
	var nowTime int64
	if monotonic {
		nowTime = int64(time.Now().Nanosecond())
	} else {
		nowTime = getBootTimeNanoseconds()
	}
	diff := ktime - nowTime
	t := time.Now().Add(time.Duration(diff))
	return t, nil
}
