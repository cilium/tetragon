// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// This package contains helpers for configuring test runners that automate test
// setup/teardown. In general, every e2e test should at least have something like the
// following:
//
//     func TestMain(m *testing.M) {
//     	testenv = runners.NewRunner().Setup()
//     	os.Exit(testenv.Run(m))
//     }
//
// The above code snippet will automatically bootstrap the cluster, install Cilium and
// Tetragon, port forward the necessary ports for gRPC and metrics, and register hooks to
// automatically clean up resources at the end of the test.
package runners
