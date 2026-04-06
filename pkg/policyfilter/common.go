// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"math"

	"github.com/google/uuid"
)

const (
	// we reserve 0 as a special value to indicate no filtering
	NoFilterPolicyID         = 0
	NoFilterID               = PolicyID(NoFilterPolicyID)
	FirstValidFilterPolicyID = NoFilterPolicyID + 1

	// AllPodsPolicyID is a reserved synthetic policy id that tracks all pod cgroup ids.
	AllPodsPolicyID = PolicyID(math.MaxUint32)

	// Special CgroupID to store the hostSelector mode.
	HostSelectorMode = math.MaxUint64
)

const (
	// polMapSize is the number of entries for the (inner) policy map. It
	// should be large enough to accommodate the number of containers
	// running in a system.
	polMapSize = 32768

	// same as POLICY_FILTER_MAX_POLICIES in policy_filter.h
	polMaxPolicies = 128
)

type PolicyID uint32
type PodID uuid.UUID
type CgroupID uint64
type StateID uint64
