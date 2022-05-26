//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package yamlhelpers

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"
)

// AssertMarshalRoundTrip makes sure you can marshal an object and that unmarshalling it
// produces the same object.
func AssertMarshalRoundTrip(t *testing.T, o interface{}) bool {
	out, err := yaml.Marshal(o)
	if !assert.NoError(t, err, "`%#v` should marshal", o) {
		return false
	}

	o2 := reflect.New(reflect.TypeOf(o).Elem()).Interface()
	err = yaml.UnmarshalStrict(out, o2)
	if !assert.NoError(t, err, "`%#v` should unmarshal from marshaled value", o) {
		return false
	}

	return assert.Equal(t, o, o2, "values should be equal")
}

// AssertUnmarshalRoundTrip unmarshals an object, makes sure you can remarshal it, and
// makes sure that unmarshalling again produces the same object.
func AssertUnmarshalRoundTrip(t *testing.T, b []byte, o interface{}) bool {
	err := yaml.Unmarshal(b, o)
	if !assert.NoError(t, err, "`%s` should unmarshal", string(b)) {
		return false
	}

	return AssertMarshalRoundTrip(t, o)
}

// AssertUnmarshal unmarshals an object and makes sure that it unmarshals
func AssertUnmarshal(t *testing.T, b []byte, o interface{}) bool {
	err := yaml.Unmarshal(b, o)
	if !assert.NoError(t, err, "`%v` should unmarshal", o) {
		return false
	}
	return true
}

// AssertMarshal unmarshals an object and makes sure that it unmarshals
func AssertMarshal(t *testing.T, b []byte, o interface{}) bool {
	_, err := yaml.Marshal(o)
	if !assert.NoError(t, err, "`%s` should marshal", string(b)) {
		return false
	}
	return true
}
