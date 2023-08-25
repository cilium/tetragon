// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	pb "github.com/cilium/cilium/api/v1/flow"
)

// CompareKafka returns true if both Kafka flows are identical
func CompareKafka(a, b *pb.Kafka) bool {
	return a.ErrorCode == b.ErrorCode &&
		a.ApiVersion == b.ApiVersion &&
		a.ApiKey == b.ApiKey &&
		a.CorrelationId == b.CorrelationId &&
		a.Topic == b.Topic
}
