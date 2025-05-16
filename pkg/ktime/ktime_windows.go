// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ktime

import (
	"time"
)

func NanoTimeSince(ktime int64) (time.Duration, error) {
	nowTime := int64(time.Now().Nanosecond())
	diff := nowTime - ktime
	return time.Duration(diff), nil
}

func Monotonic() (time.Duration, error) {
	return time.Duration(time.Now().Nanosecond()), nil
}

func WindowsToUnixTime(winTime uint64) uint64 {
	// Difference between Windows epoch (1601) and Unix epoch (1970) in 100-nanosecond intervals
	const epochDifference = 116444736000000000
	unixTime := (winTime - epochDifference) / 10000 // Convert 100-ns units to microseconds
	return unixTime
}

func DecodeKtime(ktime int64, _ bool) (time.Time, error) {
	var t time.Time

	uTime := WindowsToUnixTime(uint64(ktime))
	t = time.UnixMilli(int64(uTime))

	return t, nil

}
