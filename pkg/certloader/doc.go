// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package certloader builds a reloadable [crypto/tls.Config] backed by files
// on disk, so cert rotation does not require a server restart. The package
// is transport-agnostic — the produced [crypto/tls.Config] is consumed by
// the Tetragon gRPC server.
//
// The design — directory-watched material, atomic snapshot swapped on
// reload, [crypto/tls.Config.GetConfigForClient] pinning a snapshot for the
// duration of each handshake — is adapted from
// [cilium/cilium/pkg/crypto/certloader] (Apache-2.0).
//
// [cilium/cilium/pkg/crypto/certloader]: https://github.com/cilium/cilium/tree/main/pkg/crypto/certloader
package certloader
