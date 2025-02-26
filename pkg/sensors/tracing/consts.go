// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import "errors"

const (
	enforcerDataMapName = "enforcer_data"
)

const (
	CharBufErrorENOMEM      = -1
	CharBufErrorPageFault   = -2
	CharBufErrorTooLarge    = -3
	CharBufSavedForRetprobe = -4

	// The following values could be fine tuned if either those feature use too
	// much kernel memory when enabled.
	stackTraceMapMaxEntries = 32768
	ratelimitMapMaxEntries  = 32768
	fdInstallMapMaxEntries  = 32000
	enforcerMapMaxEntries   = 32768
	overrideMapMaxEntries   = 32768
)

var errParseStringSize = errors.New("error parsing string size from binary")

// this is from bpf/process/types/basic.h 'MAX_STRING'
const maxStringSize = 4096
const maxStringSizeSmall = 510
const maxStringSizeTiny = 144

func kprobeCharBufErrorToString(e int32) string {
	switch e {
	case CharBufErrorENOMEM:
		return "CharBufErrorENOMEM"
	case CharBufErrorTooLarge:
		return "CharBufErrorBufTooLarge"
	case CharBufErrorPageFault:
		return "CharBufErrorPageFault"
	}
	return "CharBufErrorUnknown"
}
