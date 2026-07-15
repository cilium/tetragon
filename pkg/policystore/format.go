// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policystore

import (
	"fmt"
)

type PolicyID struct {
	Name      string // policy name
	Namespace string // can be empty
	Domain    string // i.e. grpc, static, k8s
}

// returns the string representation of the policy ID
func (id PolicyID) String() string {
	return fmt.Sprintf("%s:%s:%s", id.Name, id.Namespace, id.Domain)
}

type PolicyWithState struct {
	YAML    string `json:"yaml"`
	Enabled bool   `json:"enabled"`
}

type PolicyEntry struct {
	ID  PolicyID
	Pol PolicyWithState
}

type PolicyStore interface {
	Get(id PolicyID) (PolicyWithState, bool)
	Put(id PolicyID, state PolicyWithState) error
	Delete(id PolicyID) error
	List() []PolicyEntry
}
