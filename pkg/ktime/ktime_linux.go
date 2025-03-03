// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ktime

import (
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	clk := int32(unix.CLOCK_MONOTONIC)
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return 0, err
	}
	diff := currentTime.Nano() - ktime
	return time.Duration(diff), nil
}

func Monotonic() (time.Duration, error) {
	clk := int32(unix.CLOCK_MONOTONIC)
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return 0, err
	}
	return time.Duration(currentTime.Nano()), nil
}

func DecodeKtime(ktime int64, monotonic bool) (time.Time, error) {
	var clk int32
	if monotonic {
		clk = int32(unix.CLOCK_MONOTONIC)
	} else {
		clk = int32(unix.CLOCK_BOOTTIME)
	}
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return time.Time{}, err
	}
	diff := ktime - currentTime.Nano()
	t := time.Now().Add(time.Duration(diff))
	return t, nil
}
