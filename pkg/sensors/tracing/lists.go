// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/ftrace"
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
	ListTypeInvalid           = -1
	ListTypeNone              = 0
	ListTypeSyscalls          = 1
	ListTypeGeneratedSyscalls = 2
	ListTypeGeneratedFtrace   = 3
)

var listTypeTable = map[string]uint32{
	"":                   ListTypeNone,
	"syscalls":           ListTypeSyscalls,
	"generated_syscalls": ListTypeGeneratedSyscalls,
	"generated_ftrace":   ListTypeGeneratedFtrace,
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

	// Add prefix to syscalls list
	if listTypeFromString(list.Type) == ListTypeSyscalls {
		for idx := range list.Values {
			symbol, err := arch.AddSyscallPrefix(list.Values[idx])
			if err != nil {
				return err
			}
			list.Values[idx] = symbol
		}
		return nil
	}

	// Generate syscalls list
	if listTypeFromString(list.Type) == ListTypeGeneratedSyscalls {
		if len(list.Values) != 0 {
			return fmt.Errorf("Error generated list '%s' has generate and values", list.Name)
		}
		tmp, err := btf.GetSyscallsList()
		if err != nil {
			return err
		}
		list.Values = append(list.Values, tmp...)
		return nil
	}

	// Generate ftrace list
	if listTypeFromString(list.Type) == ListTypeGeneratedFtrace {
		if list.Pattern == "" {
			return fmt.Errorf("Error generated ftrace list '%s' must specify pattern", list.Name)
		}
		list.Values, err = ftrace.ReadAvailFuncs(list.Pattern)
		return err
	}

	return nil
}
