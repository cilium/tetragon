// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/synthetic"
)

// Test types for serialization tests
type testEvent struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

type testData struct {
	Value int    `json:"value"`
	Name  string `json:"name"`
}

type testWithSlice struct {
	Items []testData `json:"items"`
}

type testWithMap struct {
	Data map[string]int `json:"data"`
}

type testWithIntKey struct {
	Data map[int]string `json:"data"`
}

type testWithArray struct {
	Arr [3]int `json:"arr"`
}

type testWithBool struct {
	Active bool `json:"active"`
}

type testWithFloats struct {
	F32 float32 `json:"f32"`
	F64 float64 `json:"f64"`
}

type testWithPointer struct {
	Ptr *testData `json:"ptr"`
}

type testWithAllInts struct {
	I   int   `json:"i"`
	I8  int8  `json:"i8"`
	I16 int16 `json:"i16"`
	I32 int32 `json:"i32"`
	I64 int64 `json:"i64"`
}

type testWithAllUints struct {
	U   uint   `json:"u"`
	U8  uint8  `json:"u8"`
	U16 uint16 `json:"u16"`
	U32 uint32 `json:"u32"`
	U64 uint64 `json:"u64"`
}

type testIgnoredField struct {
	Public  string `json:"public"`
	Ignored string `json:"-"`
	private string //nolint:unused
}

type testEmptyTag struct {
	Field string `json:",omitempty"`
}

type testNoTag struct {
	Field string
}

type testUnsupportedField struct {
	Ch chan int `json:"ch"`
}

type testMapWithComplexValue struct {
	Data map[string]testData `json:"data"`
}

type testValueType struct {
	X int `json:"x"`
}

type testWithChan struct {
	Data any `json:"data"`
}

type testWithChanSlice struct {
	Items []any `json:"items"`
}

type testWithChanMap struct {
	Data map[string]any `json:"data"`
}

type testWithChanArray struct {
	Arr [2]any `json:"arr"`
}

func init() {
	synthetic.RegisterType((*testEvent)(nil))
	synthetic.RegisterType((*testData)(nil))
	synthetic.RegisterType((*testWithSlice)(nil))
	synthetic.RegisterType((*testWithMap)(nil))
	synthetic.RegisterType((*testWithIntKey)(nil))
	synthetic.RegisterType((*testWithArray)(nil))
	synthetic.RegisterType((*testWithBool)(nil))
	synthetic.RegisterType((*testWithFloats)(nil))
	synthetic.RegisterType((*testWithPointer)(nil))
	synthetic.RegisterType((*testWithAllInts)(nil))
	synthetic.RegisterType((*testWithAllUints)(nil))
	synthetic.RegisterType((*testIgnoredField)(nil))
	synthetic.RegisterType((*testEmptyTag)(nil))
	synthetic.RegisterType((*testNoTag)(nil))
	synthetic.RegisterType((*testUnsupportedField)(nil))
	synthetic.RegisterType((*testMapWithComplexValue)(nil))
	// Non-pointer registration for testValueType
	synthetic.InterfaceRegistry["test.valueType"] = func() any { return new(testValueType) }
	synthetic.RegisterType((*testWithChan)(nil))
}

func TestMarshalEvent(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"simple struct", &testData{Value: 42, Name: "test"},
			`{"synthetic_type":"*synthetic_test.testData","synthetic_value":{"name":"test","value":42}}`},
		{"struct with interface", &testEvent{ID: 1, Message: "hello", Data: &testData{Value: 100, Name: "nested"}},
			`{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"data":{"synthetic_type":"*synthetic_test.testData","synthetic_value":{"name":"nested","value":100}},"id":1,"message":"hello"}}`},
		{"nil interface", &testEvent{ID: 2, Data: nil},
			`{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"data":null,"id":2,"message":""}}`},
		{"slice", &testWithSlice{Items: []testData{{Value: 1, Name: "a"}}},
			`{"synthetic_type":"*synthetic_test.testWithSlice","synthetic_value":{"items":[{"name":"a","value":1}]}}`},
		{"empty slice", &testWithSlice{Items: []testData{}},
			`{"synthetic_type":"*synthetic_test.testWithSlice","synthetic_value":{"items":[]}}`},
		{"nil slice", &testWithSlice{Items: nil},
			`{"synthetic_type":"*synthetic_test.testWithSlice","synthetic_value":{"items":null}}`},
		{"array", &testWithArray{Arr: [3]int{10, 20, 30}},
			`{"synthetic_type":"*synthetic_test.testWithArray","synthetic_value":{"arr":[10,20,30]}}`},
		{"bool true", &testWithBool{Active: true},
			`{"synthetic_type":"*synthetic_test.testWithBool","synthetic_value":{"active":true}}`},
		{"bool false", &testWithBool{Active: false},
			`{"synthetic_type":"*synthetic_test.testWithBool","synthetic_value":{"active":false}}`},
		{"floats", &testWithFloats{F32: 3.14, F64: 2.718281828},
			`{"synthetic_type":"*synthetic_test.testWithFloats","synthetic_value":{"f32":3.14,"f64":2.718281828}}`},
		{"pointer nil", &testWithPointer{Ptr: nil},
			`{"synthetic_type":"*synthetic_test.testWithPointer","synthetic_value":{"ptr":null}}`},
		{"pointer non-nil", &testWithPointer{Ptr: &testData{Value: 42, Name: "ptr"}},
			`{"synthetic_type":"*synthetic_test.testWithPointer","synthetic_value":{"ptr":{"name":"ptr","value":42}}}`},
		{"map", &testWithMap{Data: map[string]int{"x": 10}},
			`{"synthetic_type":"*synthetic_test.testWithMap","synthetic_value":{"data":{"x":10}}}`},
		{"empty map", &testWithMap{Data: map[string]int{}},
			`{"synthetic_type":"*synthetic_test.testWithMap","synthetic_value":{"data":{}}}`},
		{"nil map", &testWithMap{Data: nil},
			`{"synthetic_type":"*synthetic_test.testWithMap","synthetic_value":{"data":null}}`},
		{"int key map", &testWithIntKey{Data: map[int]string{1: "one"}},
			`{"synthetic_type":"*synthetic_test.testWithIntKey","synthetic_value":{"data":{"1":"one"}}}`},
		{"all ints", &testWithAllInts{I: 1, I8: 2, I16: 3, I32: 4, I64: 5},
			`{"synthetic_type":"*synthetic_test.testWithAllInts","synthetic_value":{"i":1,"i16":3,"i32":4,"i64":5,"i8":2}}`},
		{"all uints", &testWithAllUints{U: 1, U8: 2, U16: 3, U32: 4, U64: 18446744073709551615},
			`{"synthetic_type":"*synthetic_test.testWithAllUints","synthetic_value":{"u":1,"u16":3,"u32":4,"u64":18446744073709551615,"u8":2}}`},
		{"ignored field", &testIgnoredField{Public: "visible", Ignored: "hidden", private: "hidden2"},
			`{"synthetic_type":"*synthetic_test.testIgnoredField","synthetic_value":{"public":"visible"}}`},
		{"empty tag", &testEmptyTag{Field: "value"},
			`{"synthetic_type":"*synthetic_test.testEmptyTag","synthetic_value":{"Field":"value"}}`},
		{"no tag", &testNoTag{Field: "value"},
			`{"synthetic_type":"*synthetic_test.testNoTag","synthetic_value":{"Field":"value"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := synthetic.Serializer{}.Marshal(tt.input)
			if err != nil {
				t.Fatalf("MarshalEvent failed: %v", err)
			}

			if string(data) != tt.expected {
				t.Errorf("JSON mismatch:\ngot:  %s\nwant: %s", data, tt.expected)
			}
		})
	}
}

func TestMarshalErrors(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		wantError string
	}{
		{"channel in interface field", &testWithChan{Data: make(chan int)}, "failed to marshal interface value"},
		{"channel in slice", &testWithChanSlice{Items: []any{make(chan int)}}, "index 0"},
		{"channel in map", &testWithChanMap{Data: map[string]any{"key": make(chan int)}}, "map key"},
		{"channel in array", &testWithChanArray{Arr: [2]any{make(chan int), nil}}, "index 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := synthetic.Serializer{}.Marshal(tt.input)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestUnmarshalEvent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected any
	}{
		{"simple struct",
			`{"synthetic_type":"*synthetic_test.testData","synthetic_value":{"value":42,"name":"test"}}`,
			&testData{Value: 42, Name: "test"}},
		{"struct with interface",
			`{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"id":1,"message":"hello","data":{"synthetic_type":"*synthetic_test.testData","synthetic_value":{"value":100,"name":"nested"}}}}`,
			&testEvent{ID: 1, Message: "hello", Data: &testData{Value: 100, Name: "nested"}}},
		{"nil interface",
			`{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"id":2,"data":null}}`,
			&testEvent{ID: 2, Data: nil}},
		{"slice",
			`{"synthetic_type":"*synthetic_test.testWithSlice","synthetic_value":{"items":[{"value":1,"name":"a"},{"value":2,"name":"b"}]}}`,
			&testWithSlice{Items: []testData{{Value: 1, Name: "a"}, {Value: 2, Name: "b"}}}},
		{"empty slice",
			`{"synthetic_type":"*synthetic_test.testWithSlice","synthetic_value":{"items":[]}}`,
			&testWithSlice{Items: []testData{}}},
		{"array",
			`{"synthetic_type":"*synthetic_test.testWithArray","synthetic_value":{"arr":[10,20,30]}}`,
			&testWithArray{Arr: [3]int{10, 20, 30}}},
		{"bool true",
			`{"synthetic_type":"*synthetic_test.testWithBool","synthetic_value":{"active":true}}`,
			&testWithBool{Active: true}},
		{"bool false",
			`{"synthetic_type":"*synthetic_test.testWithBool","synthetic_value":{"active":false}}`,
			&testWithBool{Active: false}},
		{"floats",
			`{"synthetic_type":"*synthetic_test.testWithFloats","synthetic_value":{"f32":3.14,"f64":2.718281828}}`,
			&testWithFloats{F32: 3.14, F64: 2.718281828}},
		{"pointer nil",
			`{"synthetic_type":"*synthetic_test.testWithPointer","synthetic_value":{"ptr":null}}`,
			&testWithPointer{Ptr: nil}},
		{"pointer non-nil",
			`{"synthetic_type":"*synthetic_test.testWithPointer","synthetic_value":{"ptr":{"value":42,"name":"ptr"}}}`,
			&testWithPointer{Ptr: &testData{Value: 42, Name: "ptr"}}},
		{"map",
			`{"synthetic_type":"*synthetic_test.testWithMap","synthetic_value":{"data":{"x":10,"y":20}}}`,
			&testWithMap{Data: map[string]int{"x": 10, "y": 20}}},
		{"empty map",
			`{"synthetic_type":"*synthetic_test.testWithMap","synthetic_value":{"data":{}}}`,
			&testWithMap{Data: map[string]int{}}},
		{"int key map",
			`{"synthetic_type":"*synthetic_test.testWithIntKey","synthetic_value":{"data":{"1":"one","2":"two"}}}`,
			&testWithIntKey{Data: map[int]string{1: "one", 2: "two"}}},
		{"all ints",
			`{"synthetic_type":"*synthetic_test.testWithAllInts","synthetic_value":{"i":1,"i8":2,"i16":3,"i32":4,"i64":5}}`,
			&testWithAllInts{I: 1, I8: 2, I16: 3, I32: 4, I64: 5}},
		{"all uints",
			`{"synthetic_type":"*synthetic_test.testWithAllUints","synthetic_value":{"u":1,"u8":2,"u16":3,"u32":4,"u64":18446744073709551615}}`,
			&testWithAllUints{U: 1, U8: 2, U16: 3, U32: 4, U64: 18446744073709551615}},
		{"empty tag",
			`{"synthetic_type":"*synthetic_test.testEmptyTag","synthetic_value":{"Field":"value"}}`,
			&testEmptyTag{Field: "value"}},
		{"no tag",
			`{"synthetic_type":"*synthetic_test.testNoTag","synthetic_value":{"Field":"value"}}`,
			&testNoTag{Field: "value"}},
		{"non-pointer type in nested interface",
			`{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"id":1,"message":"test","data":{"synthetic_type":"test.valueType","synthetic_value":{"x":42}}}}`,
			&testEvent{ID: 1, Message: "test", Data: testValueType{X: 42}}},
		{"ignored fields in input",
			`{"synthetic_type":"*synthetic_test.testIgnoredField","synthetic_value":{"public":"visible","Ignored":"hidden","private":"hidden2"}}`,
			&testIgnoredField{Public: "visible"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := synthetic.Serializer{}.Unmarshal([]byte(tt.input))
			if err != nil {
				t.Fatalf("UnmarshalEvent failed: %v", err)
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("result = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestUnmarshalEventErrors(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError string
	}{
		// Wrapper errors
		{"invalid JSON", `{invalid`, "failed to unmarshal event wrapper"},
		{"missing type", `{"synthetic_value":{"value":1}}`, "missing type in event wrapper"},
		{"unknown type", `{"synthetic_type":"unknown.Type","synthetic_value":{}}`, "unknown type"},
		{"missing value", `{"synthetic_type":"*synthetic_test.testData"}`, "EOF"},

		// Type mismatch errors
		{"value not object", `{"synthetic_type":"*synthetic_test.testData","synthetic_value":"not-a-json-object"}`, "expected map for struct"},
		{"wrong type for struct", `{"synthetic_type":"*synthetic_test.testData","synthetic_value":[1,2,3]}`, "expected map for struct"},
		{"wrong type for slice", `{"synthetic_type":"*synthetic_test.testWithSlice","synthetic_value":{"items":"not-an-array"}}`, "expected array for slice"},
		{"wrong type for array", `{"synthetic_type":"*synthetic_test.testWithArray","synthetic_value":{"arr":"not-an-array"}}`, "expected array for array"},
		{"wrong type for map", `{"synthetic_type":"*synthetic_test.testWithMap","synthetic_value":{"data":[1,2,3]}}`, "expected map for map"},

		// Nested type errors
		{"nested non-string type", `{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"id":1,"message":"test","data":{"synthetic_type":123,"synthetic_value":{}}}}`, "synthetic_type must be string"},
		{"nested unknown type", `{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"id":1,"message":"test","data":{"synthetic_type":"unknown.Type","synthetic_value":{}}}}`, "unknown type"},
		{"nested value error", `{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"id":1,"message":"test","data":{"synthetic_type":"*synthetic_test.testData","synthetic_value":{"value":"bad","name":"test"}}}}`, "invalid int"},
		{"interface without wrapper", `{"synthetic_type":"*synthetic_test.testEvent","synthetic_value":{"id":1,"message":"test","data":"plain-string"}}`, "interface field without typed wrapper"},

		// Field parsing errors
		{"invalid int field", `{"synthetic_type":"*synthetic_test.testData","synthetic_value":{"value":"not-an-int","name":"test"}}`, "invalid int"},
		{"invalid int in struct", `{"synthetic_type":"*synthetic_test.testWithAllInts","synthetic_value":{"i":"not-an-int","i8":0,"i16":0,"i32":0,"i64":0}}`, "invalid int"},
		{"invalid uint", `{"synthetic_type":"*synthetic_test.testWithAllUints","synthetic_value":{"u":"not-a-uint","u8":0,"u16":0,"u32":0,"u64":0}}`, "invalid uint"},
		{"invalid float", `{"synthetic_type":"*synthetic_test.testWithFloats","synthetic_value":{"f32":"not-a-float","f64":0}}`, "invalid float"},
		{"bool to non-bool", `{"synthetic_type":"*synthetic_test.testWithAllInts","synthetic_value":{"i":true,"i8":0,"i16":0,"i32":0,"i64":0}}`, "cannot assign bool"},
		{"unsupported field type", `{"synthetic_type":"*synthetic_test.testUnsupportedField","synthetic_value":{"ch":"something"}}`, "cannot assign"},

		// Collection element errors
		{"slice element error", `{"synthetic_type":"*synthetic_test.testWithSlice","synthetic_value":{"items":[{"value":"bad","name":"test"}]}}`, "index"},
		{"array element error", `{"synthetic_type":"*synthetic_test.testWithArray","synthetic_value":{"arr":["not-an-int",2,3]}}`, "invalid int"},
		{"map key error", `{"synthetic_type":"*synthetic_test.testWithIntKey","synthetic_value":{"data":{"not-an-int":"value"}}}`, "map key"},
		{"map value error", `{"synthetic_type":"*synthetic_test.testMapWithComplexValue","synthetic_value":{"data":{"key":{"value":"not-an-int","name":"test"}}}}`, "invalid int"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := synthetic.Serializer{}.Unmarshal([]byte(tt.input))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestUnmarshalInvalidFactoryResult(t *testing.T) {
	tests := []struct {
		name      string
		typeName  string
		factory   func() any
		input     string
		wantError string
	}{
		{
			name:      "nil factory result",
			typeName:  "nilFactory",
			factory:   func() any { return nil },
			input:     `{"synthetic_type":"nilFactory","synthetic_value":{}}`,
			wantError: "non-nil pointer",
		},
		{
			name:      "non-pointer factory result",
			typeName:  "nonPtrFactory",
			factory:   func() any { return testData{Value: 1, Name: "not-a-pointer"} },
			input:     `{"synthetic_type":"nonPtrFactory","synthetic_value":{"value":42,"name":"test"}}`,
			wantError: "non-nil pointer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synthetic.InterfaceRegistry[tt.typeName] = tt.factory
			defer delete(synthetic.InterfaceRegistry, tt.typeName)

			_, err := synthetic.Serializer{}.Unmarshal([]byte(tt.input))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantError)
			}
		})
	}
}
