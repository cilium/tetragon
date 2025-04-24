// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import "errors"

var errParseStringSize = errors.New("error parsing string size from binary")

// this is from bpf/process/types/basic.h 'MAX_STRING'
const maxStringSize = 4096

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
