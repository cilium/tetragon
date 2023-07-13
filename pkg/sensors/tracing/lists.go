// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func hasList(name string, lists []v1alpha1.ListSpec) bool {
	for idx := range lists {
		list := lists[idx]
		if list.Name == name {
			return true
		}
	}
	return false
}

const (
	ListTypeInvalid = -1
	ListTypeNone    = 0
)

var listTypeTable = map[string]uint32{
	"": ListTypeNone,
}

func listTypeFromString(s string) int32 {
	typ, ok := listTypeTable[strings.ToLower(s)]
	if !ok {
		return ListTypeInvalid
	}
	return int32(typ)
}

func preValidateList(list *v1alpha1.ListSpec) (err error) {
	if listTypeFromString(list.Type) == ListTypeInvalid {
		return fmt.Errorf("Invalid list type: %s", list.Type)
	}

	return nil
}
