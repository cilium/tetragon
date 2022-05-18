// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package listmatcher

import (
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewGeneratedFile(gen, f, "eventchecker/matchers/listmatcher")

	jsonMarshal := common.GoIdent(g, "encoding/json", "Marshal")
	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")
	toLower := common.GoIdent(g, "strings", "ToLower")

	g.P(`type Operator struct {
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
            return opUnknown, ` + common.FmtErrorf(g, "Invalid value for ListMatcher operator: %s", "str") + `
        }
    }

    var (
        opUnknown   = Operator{""}
        Ordered   = Operator{"ordered"}
        Unordered = Operator{"unordered"}
        Subset    = Operator{"subset"}
    )

    // UnmarshalJSON implements json.Unmarshaler interface
    func (o *Operator) UnmarshalJSON(b []byte) error {
        var str string
        err := ` + yamlUnmarshal + `(b, &str)
        if err != nil {
            return err
        }

        str = ` + toLower + `(str)
        operator, err := operatorFromString(str)
        if err != nil {
            return err
        }

        *o = operator
        return nil
    }

    // MarshalJSON implements json.Marshaler interface
    func (o Operator) MarshalJSON() ([]byte, error) {
        return ` + jsonMarshal + `(o.slug)
    }`)

	return nil
}
