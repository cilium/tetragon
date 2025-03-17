// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

var (
	notSupportedWinErr = errors.New("not supported on windows")
)

// isList checks if a value specifies a list, and if so it returns it (or nil if list does not exist)
func isList(val string, lists []v1alpha1.ListSpec) (bool, *v1alpha1.ListSpec) {
	return false, nil
}

func preValidateLists(lists []v1alpha1.ListSpec) (err error) {
	return notSupportedWinErr
}

type listReader struct {
	lists []v1alpha1.ListSpec
}

func (lr *listReader) Read(name string, ty uint32) ([]uint32, error) {
	return []uint32{}, notSupportedWinErr
}

func getSyscallListSymbols(list *v1alpha1.ListSpec) ([]string, error) {
	return nil, notSupportedWinErr
}
