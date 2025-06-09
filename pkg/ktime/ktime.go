// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ktime

import (
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func ToProto(ktime uint64) *timestamppb.Timestamp {
	return ToProtoOpt(ktime, true)
}

func ToProtoOpt(ktime uint64, monotonic bool) *timestamppb.Timestamp {
	decodedTime, err := DecodeKtime(int64(ktime), monotonic)
	if err != nil {
		logger.GetLogger().Warn("Failed to decode ktime", "ktime", ktime)
		return timestamppb.Now()
	}
	return timestamppb.New(decodedTime)
}

func DiffKtime(start, end uint64) time.Duration {
	return time.Duration(int64(end - start))
}
