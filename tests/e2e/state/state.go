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
	// Key for storing a list of forwarded connections for gRPC
	GrpcForwardedConns = Key{slug: "GrpcForwardedConns"}
	// Key for storing a list of ports we forwarded for prometheus metics
	PromForwardedPorts = Key{slug: "PromForwardedPorts"}
	// Key for storing a list of ports we forwarded for the pprof server
	GopsForwardedPorts = Key{slug: "GopsForwardedPorts"}
	// Key for storing the minimum kernel version of all nodes in the cluster
	MinKernelVersion = Key{slug: "MinKernelVersion"}
	// Stores a list of event checkers that were used in the test
	EventCheckers = Key{slug: "EventCheckers"}
	// Key for storing the export directory for this test
	ExportDir = Key{slug: "ExportDir"}
	// Key for storing the cluster name
	ClusterName = Key{slug: "ClusterName"}
	// Key for storing test failure
	TestFailure = Key{slug: "TestFailure"}
)
