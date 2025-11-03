// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package event

import (
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Event represents a single event observed and stored by Hubble
type Event struct {
	// Timestamp when event was observed in Hubble
	Timestamp *timestamppb.Timestamp
	// Event contains the actual event
	Event any
}
