## Protobuf Field Mask utils for Go

[![Tests](https://github.com/mennanov/fieldmask-utils/actions/workflows/tests.yml/badge.svg)](https://github.com/mennanov/fieldmask-utils/actions/workflows/tests.yml)
[![Coverage](https://codecov.io/gh/mennanov/fieldmask-utils/branch/master/graph/badge.svg?token=O7HtNMO6Ra)](https://codecov.io/gh/mennanov/fieldmask-utils)

Features:

* Copy from any Go struct to any compatible Go struct with a field mask applied
* Copy from any Go struct to a `map[string]interface{}` with a field mask applied
* Extensible masks (e.g. inverse mask: copy all except those mentioned, etc.)
* Supports [Protobuf Any](https://developers.google.com/protocol-buffers/docs/proto3#any) message types.

If you're looking for a simple FieldMask library to work with protobuf messages only (not arbitrary structs) consider this tiny repo: [https://github.com/mennanov/fmutils](https://github.com/mennanov/fmutils)

### Examples

Copy from a protobuf message to a protobuf message:

```proto
// testproto/test.proto

message UpdateUserRequest {
    User user = 1;
    google.protobuf.FieldMask field_mask = 2;
}
```

```go
package main

import fieldmask_utils "github.com/mennanov/fieldmask-utils"

// A function that maps field mask field names to the names used in Go structs.
// It has to be implemented according to your needs.
// Scroll down for a reference on how to apply field masks to your gRPC services.
func naming(s string) string {
	if s == "foo" {
		return "Foo"
	}
	return s
}

func main () {
	var request UpdateUserRequest
	userDst := &testproto.User{} // a struct to copy to
	mask, _ := fieldmask_utils.MaskFromPaths(request.FieldMask.Paths, naming)
	fieldmask_utils.StructToStruct(mask, request.User, userDst)
	// Only the fields mentioned in the field mask will be copied to userDst, other fields are left intact
}
```

Copy from a protobuf message to a `map[string]interface{}`:

```go
package main

import fieldmask_utils "github.com/mennanov/fieldmask-utils"

func main() {
	var request UpdateUserRequest
	userDst := make(map[string]interface{}) // a map to copy to
	mask, _ := fieldmask_utils.MaskFromProtoFieldMask(request.FieldMask, naming)
	err := fieldmask_utils.StructToMap(mask, request.User, userDst)
	// Only the fields mentioned in the field mask will be copied to userDst, other fields are left intact
}
```

Copy with an inverse mask:

```go
package main

import fieldmask_utils "github.com/mennanov/fieldmask-utils"

func main() {
	var request UpdateUserRequest
	userDst := &testproto.User{} // a struct to copy to
	mask := fieldmask_utils.MaskInverse{"Id": nil, "Friends": fieldmask_utils.MaskInverse{"Username": nil}}
	fieldmask_utils.StructToStruct(mask, request.User, userDst)
	// Only the fields that are not mentioned in the field mask will be copied to userDst, other fields are left intact.
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
func main() {
    mask := &fieldmaskpb.FieldMask{Paths: []string{"username"}}
    mask.Normalize()
    req := &UpdateUserRequest{
        User: &User{
            Id:       1234,
            Username: "Test",
        },
    }
    if !mask.IsValid(req) {
        return
    }
    protoMask, err := fieldmask_utils.MaskFromProtoFieldMask(mask, strings.PascalCase)
    if err != nil {
        return
    }
    m := make(map[string]any)
    err = fieldmask_utils.StructToMap(protoMask, req, m)
	if err != nil {
		return
    }
	fmt.Println("Resulting map:", m)
}
```

This will result in a map that contains the fields that need to be updated with their respective values.

#### Converter hooks

When trying to assign a source field to a destination using different types, one can use the Option `WithConverterHook`.
All provided converter functions will be tried in order until src is assignable to dst or an error occured.

Below you will find an example of how to convert from string to int64 when applying a mask by specifying such converter:

```go
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

    err = fieldmask_utils.StructToStruct(mask, src, dst,
		fieldmask_utils.WithConverterHook(func(src, dst *reflect.Value) (interface{}, error) {
			data := src.Interface()

            // only care for this conversion
			if src.Kind() != reflect.String ||
				dst.Kind() != reflect.Int64 {
				return data, nil
			}

            // cast it
			raw, ok := data.(string)
			if !ok {
				return data, nil
			}

            // parse it
			return strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		}))

	fmt.Println("src:", src)
	fmt.Println("dst:", dst)
}
```

### Limitations

1.  Larger scope field masks have no effect and are not considered invalid:

    field mask strings `"a", "a.b", "a.b.c"` will result in a mask `a{b{c}}`, which is the same as `"a.b.c"`.

2.  Masks inside a protobuf `Map` are not supported.
3.  When copying from a struct to struct the destination struct must have the same fields (or a subset)
    as the source struct. Either of source or destination fields can be a pointer as long as it is a pointer to
    the type of the corresponding field.
4. `oneof` fields are represented differently in `fieldmaskpb.FieldMask` compared to `fieldmask_util.Mask`. In
    [FieldMask](https://pkg.go.dev/google.golang.org/protobuf/types/known/fieldmaskpb#:~:text=%23%20Field%20Masks%20and%20Oneof%20Fields)
    the fields are represented using their property name, in this library they are prefixed with the `oneof` name
    matching how Go generated code is laid out. This can lead to issues when converting between the two, for example
    when using `MaskFromPaths` or `MaskFromProtoFieldMask`.
