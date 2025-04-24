// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// isList checks if a value specifies a list, and if so it returns it (or nil if list does not exist)
func isList(_ string, _ []v1alpha1.ListSpec) (bool, *v1alpha1.ListSpec) {
	return false, nil
}

func preValidateLists(_ []v1alpha1.ListSpec) (err error) {
	return constants.ErrWindowsNotSupported
}

type listReader struct {
	lists []v1alpha1.ListSpec
}

func (lr *listReader) Read(name string, ty uint32) ([]uint32, error) {
	return []uint32{}, constants.ErrWindowsNotSupported
}

func getSyscallListSymbols(_ *v1alpha1.ListSpec) ([]string, error) {
	return nil, constants.ErrWindowsNotSupported
}
