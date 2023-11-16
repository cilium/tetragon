package fieldmask_utils

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/genproto/protobuf/field_mask"
)

// FieldFilter is an interface used by the copying function to filter fields that are needed to be copied.
type FieldFilter interface {
	// Filter should return a corresponding FieldFilter for the given fieldName and a boolean result. If result is true
	// then the field is copied, skipped otherwise.
	Filter(fieldName string) (FieldFilter, bool)
	// Returns true if the FieldFilter is empty. In this case all fields are copied.
	IsEmpty() bool
}

// FieldFilterContainer is a FieldFilter with additional methods Get and Set.
type FieldFilterContainer interface {
	FieldFilter
	// Get gets the FieldFilter for the given field name. Result is false if the filter is not found.
	Get(fieldName string) (filter FieldFilterContainer, result bool)
	// Set sets the FieldFilter for the given field name.
	Set(fieldName string, filter FieldFilterContainer)
}

// Mask is a tree-based implementation of a FieldFilter.
type Mask map[string]FieldFilterContainer

// Get gets the FieldFilter for the given field name. Result is false if the filter is not found.
func (m Mask) Get(fieldName string) (FieldFilterContainer, bool) {
	f, ok := m[fieldName]
	return f, ok
}

// Set sets the FieldFilter for the given field name.
func (m Mask) Set(fieldName string, filter FieldFilterContainer) {
	m[fieldName] = filter
}

// Compile time interface check.
var _ FieldFilter = Mask{}

// Filter returns true for those fieldNames that exist in the underlying map.
// Field names that start with "XXX_" are ignored as unexported.
func (m Mask) Filter(fieldName string) (FieldFilter, bool) {
	if len(m) == 0 {
		// If the mask is empty choose all the exported fields.
		return Mask{}, !strings.HasPrefix(fieldName, "XXX_")
	}
	subFilter, ok := m[fieldName]
	if !ok {
		subFilter = Mask{}
	}
	return subFilter, ok
}

// IsEmpty returns true of the mask is empty.
func (m Mask) IsEmpty() bool {
	return len(m) == 0
}

func mapToString(m map[string]FieldFilterContainer) string {
	if len(m) == 0 {
		return ""
	}
	var result []string
	for fieldName, maskNode := range m {
		r := fieldName
		var sub string
		if stringer, ok := maskNode.(fmt.Stringer); ok {
			sub = stringer.String()
		} else {
			sub = fmt.Sprint(maskNode)
		}
		if sub != "" {
			r += "{" + sub + "}"
		}
		result = append(result, r)
	}
	return strings.Join(result, ",")
}

func (m Mask) String() string {
	return mapToString(m)
}

// MaskInverse is an inversed version of a Mask (will copy all the fields except those mentioned in the mask).
type MaskInverse map[string]FieldFilterContainer

// Get gets the FieldFilter for the given field name. Result is false if the filter is not found.
func (m MaskInverse) Get(fieldName string) (FieldFilterContainer, bool) {
	f, ok := m[fieldName]
	return f, ok
}

// Set sets the FieldFilter for the given field name.
func (m MaskInverse) Set(fieldName string, filter FieldFilterContainer) {
	m[fieldName] = filter
}

// Filter returns true for those fieldNames that do NOT exist in the underlying map.
// Field names that start with "XXX_" are ignored as unexported.
func (m MaskInverse) Filter(fieldName string) (FieldFilter, bool) {
	subFilter, ok := m[fieldName]
	if !ok {
		return MaskInverse{}, !strings.HasPrefix(fieldName, "XXX_")
	}
	if subFilter == nil {
		return nil, false
	}
	return subFilter, !subFilter.IsEmpty()
}

// IsEmpty returns true if the mask is empty.
func (m MaskInverse) IsEmpty() bool {
	return len(m) == 0
}

func (m MaskInverse) String() string {
	return mapToString(m)
}

// MaskFromProtoFieldMask creates a Mask from the given FieldMask.
func MaskFromProtoFieldMask(fm *field_mask.FieldMask, naming func(string) string) (Mask, error) {
	return MaskFromPaths(fm.GetPaths(), naming)
}

// MaskInverseFromProtoFieldMask creates a MaskInverse from the given FieldMask.
func MaskInverseFromProtoFieldMask(fm *field_mask.FieldMask, naming func(string) string) (MaskInverse, error) {
	return MaskInverseFromPaths(fm.GetPaths(), naming)
}

// MaskFromPaths creates a new Mask from the given paths.
func MaskFromPaths(paths []string, naming func(string) string) (Mask, error) {
	mask, err := FieldFilterFromPaths(paths, naming, func() FieldFilterContainer {
		return make(Mask)
	})
	if mask != nil {
		return mask.(Mask), err
	}
	return nil, err
}

// MaskInverseFromPaths creates a new MaskInverse from the given paths.
func MaskInverseFromPaths(paths []string, naming func(string) string) (MaskInverse, error) {
	mask, err := FieldFilterFromPaths(paths, naming, func() FieldFilterContainer {
		return make(MaskInverse)
	})
	if mask != nil {
		return mask.(MaskInverse), err
	}
	return nil, err
}

// FieldFilterFromPaths creates a new FieldFilter from the given paths.
func FieldFilterFromPaths(paths []string, naming func(string) string, filter func() FieldFilterContainer) (FieldFilterContainer, error) {
	root := filter()
	for _, path := range paths {
		mask := root
		for _, fieldName := range strings.Split(path, ".") {
			if fieldName == "" {
				return nil, errors.Errorf("invalid fieldName FieldFilter format: \"%s\"", path)
			}
			newFieldName := naming(fieldName)
			subNode, ok := mask.Get(newFieldName)
			if !ok {
				mask.Set(newFieldName, filter())
				subNode, _ = mask.Get(newFieldName)
			}
			mask = subNode
		}
	}
	return root, nil
}

// MaskFromString creates a new Mask instance from a given string.
// Use in tests only. See FieldFilterFromString for details.
func MaskFromString(s string) Mask {
	return FieldFilterFromString(s, func() FieldFilterContainer {
		return make(Mask)
	}).(Mask)
}

// MaskInverseFromString creates a new MaskInverse instance from a given string.
// Use in tests only. See FieldFilterFromString for details.
func MaskInverseFromString(s string) MaskInverse {
	return FieldFilterFromString(s, func() FieldFilterContainer {
		return make(MaskInverse)
	}).(MaskInverse)
}

// FieldFilterFromString creates a new FieldFilterContainer from string.
// Input string is supposed to be a valid string representation of a FieldFilter like "a,b,c{d,e{f,g}},d".
// Use it in tests only as the input string is not validated and the underlying function panics in case of a
// parse error.
func FieldFilterFromString(input string, filter func() FieldFilterContainer) FieldFilterContainer {
	var fieldName []string
	mask := filter()
	masks := []FieldFilterContainer{mask}
	for pos, r := range input {
		char := string(r)
		switch char {
		case " ", "\n", "\t":
		// Skip white spaces.

		case ",":
			if len(fieldName) != 0 {
				mask.Set(strings.Join(fieldName, ""), filter())
				fieldName = nil
			}

		case "{":
			if len(fieldName) == 0 {
				panic(fmt.Sprintf("invalid mask format at position %d: got '{', expected a character", pos))
			}
			subMask := filter()
			mask.Set(strings.Join(fieldName, ""), subMask)
			fieldName = nil
			masks = append(masks, mask)
			mask = subMask

		case "}":
			if len(fieldName) != 0 {
				mask.Set(strings.Join(fieldName, ""), filter())
				fieldName = nil
			}
			mask = masks[len(masks)-1]
			masks = masks[:len(masks)-1]

		default:
			fieldName = append(fieldName, char)
		}
	}
	if len(fieldName) != 0 {
		mask.Set(strings.Join(fieldName, ""), filter())
	}
	return mask
}
