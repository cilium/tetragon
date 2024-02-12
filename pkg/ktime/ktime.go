// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ktime

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type TimeSource int

const (
	Undefined TimeSource = iota
	Unstable
	Stable
)

var timeSourceStr = map[TimeSource]string{
	Undefined: "Undefined",
	Unstable:  "Unstable",
	Stable:    "Stable",
}

var (
	bootTime       time.Time
	bootTimeSource = Undefined
)

func GetBootTime() string {
	return fmt.Sprintf("Host Boot Time: [%s] Source: [%s]", bootTime.String(), timeSourceStr[bootTimeSource])
}

func init() {
	if t, err := getBootTime("/var/log/dmesg"); err == nil {
		bootTime = t
		bootTimeSource = Stable
	} else {
		now := time.Now()
		currentTime := unix.Timespec{}
		if err := unix.ClockGettime(int32(unix.CLOCK_BOOTTIME), &currentTime); err != nil {
			return
		}

		t := time.Unix(currentTime.Sec, currentTime.Nsec).Unix()
		b := now.Unix()
		bootTime = time.Unix(b-t, 0)
		bootTimeSource = Stable
	}
}

func getBootTime(logFile string) (time.Time, error) {
	r, err := regexp.Compile(`.* setting system clock to (?P<d>[0-9\-]*)[ A-Z](?P<t>[0-9:]*) UTC.* \((.*?)\)`)
	if err != nil {
		return time.Time{}, err
	}

	re, err := regexp.Compile(`\((.*?)\)`)
	if err != nil {
		return time.Time{}, err
	}

	file, err := os.Open(logFile)
	if err != nil {
		return time.Time{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if !r.MatchString(line) {
			continue
		}

		submatchall := re.FindAllString(line, -1)
		for _, elem := range submatchall {
			elem = strings.Trim(elem, "(")
			elem = strings.Trim(elem, ")")

			n, err := strconv.ParseInt(elem, 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("failed to parse seconds %s", elem)
			}
			return time.Unix(n, 0), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return time.Time{}, err
	}

	return time.Time{}, fmt.Errorf("did not match the line in %s", logFile)
}

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

func ToProtoOptStable(ktime uint64) *timestamppb.Timestamp {
	decodedTime := bootTime.Add(time.Duration(ktime))
	return timestamppb.New(decodedTime)
}
