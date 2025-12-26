// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

const (
	CharBufErrorENOMEM      = -1
	CharBufErrorPageFault   = -2
	CharBufErrorTooLarge    = -3
	CharBufSavedForRetprobe = -4

	// The following values could be fine tuned if either those feature use too
	// much kernel memory when enabled.
	stackTraceMapMaxEntries    = 32768
	ratelimitMapMaxEntries     = 32768
	fdInstallMapMaxEntries     = 32000
	enforcerMapMaxEntries      = 32768
	overrideMapMaxEntries      = 32768
	sleepableOffloadMaxEntries = 32768
	sleepablePreloadMaxEntries = 32768
	socktrackMapMaxEntries     = 32000
)
