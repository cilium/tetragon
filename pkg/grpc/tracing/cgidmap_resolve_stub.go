// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build windows || nok8s

package tracing

// No ContainerIDResolver registration needed on platforms without cgidmap.
// eventcache.ContainerIDResolver remains nil, and the type switch gracefully
// handles the absence.
