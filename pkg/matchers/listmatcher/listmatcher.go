// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package listmatcher

import (
	json "encoding/json"
	fmt "fmt"
	strings "strings"

	yaml "sigs.k8s.io/yaml"
)

type Operator struct {
	slug string
}

func (o Operator) String() string {
	return o.slug
}

func operatorFromString(str string) (Operator, error) {
	switch str {
	case Ordered.slug:
		return Ordered, nil
	case Unordered.slug:
		return Unordered, nil
	case Subset.slug:
		return Subset, nil
	default:
		return opUnknown, fmt.Errorf("Invalid value for ListMatcher operator: %s", str)
	}
}

var (
	opUnknown = Operator{""}
	Ordered   = Operator{"ordered"}
	Unordered = Operator{"unordered"}
	Subset    = Operator{"subset"}
)

// UnmarshalJSON implements json.Unmarshaler interface
func (o *Operator) UnmarshalJSON(b []byte) error {
	var str string
	err := yaml.UnmarshalStrict(b, &str)
	if err != nil {
		return err
	}

	str = strings.ToLower(str)
	operator, err := operatorFromString(str)
	if err != nil {
		return err
	}

	*o = operator
	return nil
}

// MarshalJSON implements json.Marshaler interface
func (o Operator) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.slug)
}
