// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package state

// Key is a key that we use to store specific state in a test's context.Context
type Key struct {
	slug string
}

var (
	// Key for storing a *install.Opts
	InstallOpts = Key{slug: "InstallOpts"}
	// Key for storing a list of ports we forwarded for gRPC
	GrpcForwardedPorts = Key{slug: "GrpcForwardedPorts"}
	// Key for storing a list of ports we forwarded for prometheus metics
	PromForwardedPorts = Key{slug: "PromForwardedPorts"}
	// Key for storing the minimum kernel version of all nodes in the cluster
	MinKernelVersion = Key{slug: "MinKernelVersion"}
	// Stores a list of event checkers that were used in the test
	EventCheckers = Key{slug: "EventCheckers"}
	// Stores the most recent *testing.T
	Test = Key{slug: "Test"}
)
