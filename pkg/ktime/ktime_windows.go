// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ktime

import (
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	dll            = syscall.MustLoadDLL("kernel32.dll")
	queryCounter   = dll.MustFindProc("QueryPerformanceCounter")
	queryFrequency = dll.MustFindProc("QueryPerformanceFrequency")
)

func ToProto(ktime uint64) *timestamppb.Timestamp {
	return ToProtoOpt(ktime, true)
}

func ToProtoOpt(ktime uint64, monotonic bool) *timestamppb.Timestamp {
	decodedTime, err := DecodeKtime(int64(ktime), monotonic)
	if err != nil {
		logrus.WithError(err).WithField("ktime", ktime).Warn("Failed to decode ktime")
		return timestamppb.Now()
	}
	return timestamppb.New(decodedTime)
}

func DiffKtime(start, end uint64) time.Duration {
	return time.Duration(int64(end - start))
}

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
