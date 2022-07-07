// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// This package provides a Tetragon gRPC client multiplexer and an RPCChecker that wraps
// a MultiEventChecker and uses the gRPC multiplexer to get a stream of events from all
// Tetragon pods.
package checker
