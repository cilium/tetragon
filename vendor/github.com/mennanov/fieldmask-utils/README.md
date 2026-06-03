## Protobuf Field Mask utils for Go

[![Tests](https://github.com/mennanov/fieldmask-utils/actions/workflows/tests.yml/badge.svg)](https://github.com/mennanov/fieldmask-utils/actions/workflows/tests.yml)
[![Coverage](https://codecov.io/gh/mennanov/fieldmask-utils/branch/master/graph/badge.svg?token=O7HtNMO6Ra)](https://codecov.io/gh/mennanov/fieldmask-utils)

Features:

* Copy from any Go struct to any compatible Go struct with a field mask applied
* Copy from any Go struct to a `map[string]any` with a field mask applied
* Extensible masks (e.g. inverse mask: copy all except those mentioned, etc.)
* Supports [Protobuf Any](https://developers.google.com/protocol-buffers/docs/proto3#any) message types.

If you're looking for a simple FieldMask library to work with protobuf messages only (not arbitrary structs) consider this tiny repo: [https://github.com/mennanov/fmutils](https://github.com/mennanov/fmutils)

### Examples

Copy from a protobuf message to a protobuf message:

```go
package main

import (
	"fmt"

	fieldmask_utils "github.com/mennanov/fieldmask-utils"
	"github.com/mennanov/fieldmask-utils/testproto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// A function that maps field mask field names to the names used in Go structs.
// It has to be implemented according to your needs.
// Scroll down for a reference on how to apply field masks to your gRPC services.
func naming(s string) string {
	if s == "foo" {
		return "Foo"
	}
	return s
}

// A simple request object for these examples
var request = &testproto.UpdateUserRequest{
	User: &testproto.User{
		Username: "John Doe",
		Id:       42,
	},
	FieldMask: &fieldmaskpb.FieldMask{
		Paths: []string{"Username"},
	},
}

func main() {
	userDst := &testproto.User{} // a struct to copy to
	mask, err := fieldmask_utils.MaskFromPaths(request.FieldMask.Paths, naming)
	if err != nil {
		panic(err)
	}
	// Only the fields mentioned in the field mask will be copied to userDst, other fields are left intact
	err = fieldmask_utils.StructToStruct(mask, request.User, userDst)
	if err != nil {
		panic(err)
	}

	fmt.Println("Resulting struct:", userDst)
	// Resulting struct: username:"John Doe"
}
```

Copy from a protobuf message to a `map[string]any`:

```go
// ...

func main() {
	userDst := make(map[string]any) // a map to copy to
	mask, err := fieldmask_utils.MaskFromProtoFieldMask(request.FieldMask, naming)
	if err != nil {
		panic(err)
	}
	// Only the fields mentioned in the field mask will be copied to userDst, other fields are left intact
	err = fieldmask_utils.StructToMap(mask, request.User, userDst)
	if err != nil {
		panic(err)
	}

	fmt.Println("Resulting map:", userDst)
	// Resulting map: map[Username:John Doe]
}
```

Copy with an inverse mask:

```go
// ...

func main() {
	userDst := &testproto.User{} // a struct to copy to
	mask := fieldmask_utils.MaskInverse{"Id": nil, "Friends": fieldmask_utils.MaskInverse{"Username": nil}}
	// Only the fields mentioned in the field mask will be copied to userDst, other fields are left intact
	err := fieldmask_utils.StructToStruct(mask, request.User, userDst)
	if err != nil {
		panic(err)
	}

	fmt.Println("Resulting struct:", userDst)
	// Resulting struct: username:"John Doe"
}
```

#### Naming function

For developers that are looking for a mechanism to apply a mask field in their update endpoints using gRPC services,
there are multiple options for the naming function described above:

- Using the `CamelCase` function provided in
  the [original protobuf repository](https://github.com/golang/protobuf/blob/master/protoc-gen-go/generator/generator.go#L2648).
  This repository has been deprecated and it will potentially trigger lint errors.
    - You can copy-paste the `CamelCase` function to your own project or,
    - You can use an [Open Source alternative](https://github.com/gojaguar/jaguar) that provides the same functionality,
      already took care of [copying the code](https://github.com/gojaguar/jaguar/blob/main/strings/pascal_case.go), and also added tests.

```go
// ...

import jstrings "github.com/gojaguar/jaguar/strings"

func main() {
	mask := &fieldmaskpb.FieldMask{Paths: []string{"user.username"}}
	mask.Normalize()
	if !mask.IsValid(request) {
		panic("invalid request")
	}
	protoMask, err := fieldmask_utils.MaskFromProtoFieldMask(mask, jstrings.PascalCase)
	if err != nil {
		panic(err)
	}
	m := make(map[string]any)
	err = fieldmask_utils.StructToMap(protoMask, request, m)
	if err != nil {
		panic(err)
	}
	fmt.Println("Resulting map:", m)
	// Resulting map: map[User:map[Username:John Doe]]
}
```

This will result in a map that contains the fields that need to be updated with their respective values.

#### Converter hooks

When trying to assign a source field to a destination using different types, one can use the Option `WithConverterHook`.
All provided converter functions will be tried in order until src is assignable to dst or an error occured.

Below you will find an example of how to convert from string to int64 when applying a mask by specifying such converter:

```go
// ...

type A struct {
    Field1 string
}
type B struct {
    Field1 int64
}

func main() {
	src := &A{
		Field1: "   42   ",
	}
	dst := &B{}
	mask := fieldmask_utils.MaskFromString("Field1")

	err := fieldmask_utils.StructToStruct(mask, src, dst,
		fieldmask_utils.WithConverterHook(func(src, dst *reflect.Value) (any, error) {
			if src.Type() != reflect.TypeFor[string]() ||
				dst.Type() != reflect.TypeFor[int64]() {
				return src.Interface(), nil
			}
			return strconv.ParseInt(strings.TrimSpace(src.Interface().(string)), 10, 64)
		}))
	if err != nil {
		panic(err)
	}

	fmt.Println("src:", src)
	fmt.Println("dst:", dst)
	// src: &{   42   }
	// dst: &{42}
}
```

Conversion example from `*timestamppb.Timestamp` to `time.Time`:

```go
// ...

import "google.golang.org/protobuf/types/known/timestamppb"

type A struct {
    Field1 *timestamppb.Timestamp
}
type B struct {
    Field1 time.Time
}

func main() {
	src := &A{
		Field1: &timestamppb.Timestamp{
			Seconds: 1780396738,
			Nanos:   42,
		},
	}
	dst := &B{}
	mask := fieldmask_utils.MaskFromString("Field1")

	err := fieldmask_utils.StructToStruct(mask, src, dst,
		fieldmask_utils.WithConverterHook(func(src, dst *reflect.Value) (any, error) {
			if src.Type() != reflect.TypeFor[*timestamppb.Timestamp]() ||
				dst.Type() != reflect.TypeFor[time.Time]() {
				return src.Interface(), nil
			}
			return src.Interface().(*timestamppb.Timestamp).AsTime(), nil
		}))
	if err != nil {
		panic(err)
	}

	fmt.Println("src:", src)
	fmt.Println("dst:", dst)
	// src: &{seconds:1780396738 nanos:42}
	// dst: &{2026-06-02 10:38:58.000000042 +0000 UTC}
}
```

### Limitations

1.  Larger scope field masks have no effect and are not considered invalid:

    field mask strings `"a", "a.b", "a.b.c"` will result in a mask `a{b{c}}`, which is the same as `"a.b.c"`.

2.  Masks inside a protobuf `Map` are not supported.
3.  When copying from a struct to struct the destination struct must have the same fields (or a subset)
    as the source struct. Either of source or destination fields can be a pointer as long as it is a pointer to
    the type of the corresponding field.
    You can overcome this limitation by providing converter hooks.
    A common use-case would be to copy fields of different types (including struct to primitive).
    See the example [Converter hooks](#converter-hooks).
4. `oneof` fields are represented differently in `fieldmaskpb.FieldMask` compared to `fieldmask_util.Mask`. In
    [FieldMask](https://pkg.go.dev/google.golang.org/protobuf/types/known/fieldmaskpb#:~:text=%23%20Field%20Masks%20and%20Oneof%20Fields)
    the fields are represented using their property name, in this library they are prefixed with the `oneof` name
    matching how Go generated code is laid out. This can lead to issues when converting between the two, for example
    when using `MaskFromPaths` or `MaskFromProtoFieldMask`.
