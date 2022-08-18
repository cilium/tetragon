// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// This package provides a multiplexer for combine one or more gRPC event streams into
// a single stream. Useful for running the eventchecker across multiple gRPC connections
// simultaneously, for example in a multi-node cluster.
package multiplexer
