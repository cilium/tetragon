// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package alignchecker

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf/btf"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/policystats"
	"github.com/cilium/tetragon/pkg/sensors/cgroup/cgrouptrackmap"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
)

var defaultChecks = map[string][]any{
	// from perf_event_output
	"msg_exit":         {processapi.MsgExitEvent{}},
	"msg_test":         {testapi.MsgTestEvent{}},
	"msg_execve_key":   {processapi.MsgExecveKey{}},
	"execve_map_value": {execvemap.ExecveValue{}},
	"msg_cgroup_event": {processapi.MsgCgroupEvent{}},
	"msg_cred":         {processapi.MsgGenericCred{}},

	// configuration
	"event_config":  {tracingapi.EventConfig{}},
	"tetragon_conf": {confmap.TetragonConfValue{}},

	// cgroup
	"cgroup_tracking_value": {cgrouptrackmap.CgrpTrackingValue{}},

	// metrics
	"kernel_stats": {processapi.KernelStats{}},

	// policy stats
	"policy_stats": {policystats.PolicyStats{}},
}

// CheckStructAlignmentsDefault calls CheckStructAlignments with the default alignment defaultChecks.
func CheckStructAlignmentsDefault(pathToObj string) error {
	return CheckStructAlignments(pathToObj, defaultChecks, true)
}

// CheckStructAlignments defaultChecks whether size and offsets match of the given
// C and Go structs which are listed in the given toCheck map (C type name =>
// Go type).
//
// C struct layout is extracted from the given ELF object file's BTF info.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(pathToObj string, toCheck map[string][]any, checkOffsets bool) error {
	spec, err := btf.LoadSpec(pathToObj)
	if err != nil {
		return fmt.Errorf("cannot parse BTF debug info %s: %w", pathToObj, err)
	}

	structInfo, err := getStructInfosFromBTF(spec, toCheck)
	if err != nil {
		return fmt.Errorf("cannot extract struct info from BTF %s: %w", pathToObj, err)
	}

	for cName, goStructs := range toCheck {
		if err := check(cName, goStructs, structInfo, checkOffsets); err != nil {
			return err
		}
	}
	return nil
}

type structInfo struct {
	size         uint32
	fieldOffsets map[string]uint32
}

func getStructInfosFromBTF(types *btf.Spec, toCheck map[string][]any) (map[string]*structInfo, error) {
	structs := make(map[string]*structInfo)
	for name := range toCheck {
		ts, err := types.AnyTypesByName(name)
		if err != nil {
			return nil, fmt.Errorf("looking up type %s by name: %w", name, err)
		}

		si, err := getStructInfoFromBTF(ts)
		if err != nil {
			return nil, err
		}

		structs[name] = si
	}

	return structs, nil
}

// getStructInfoFromBTF: returns the structInfo from a list of btf types.
func getStructInfoFromBTF(ts []btf.Type) (*structInfo, error) {
	var infos []*structInfo
	for _, t := range ts {
		switch typ := t.(type) {
		case *btf.Typedef:
			// Resolve Typedefs to their target types.
			si, err := getStructInfoFromBTF([]btf.Type{typ.Type})
			if err != nil {
				return nil, err
			}
			infos = append(infos, si)

		case *btf.Int:
			infos = append(infos, &structInfo{
				size:         typ.Size,
				fieldOffsets: nil,
			})

		case *btf.Struct:
			infos = append(infos, &structInfo{
				size:         typ.Size,
				fieldOffsets: memberOffsets(typ.Members),
			})

		case *btf.Union:
			infos = append(infos, &structInfo{
				size:         typ.Size,
				fieldOffsets: memberOffsets(typ.Members),
			})
		}
	}

	switch len(infos) {
	case 0:
		return nil, fmt.Errorf("unsupported types: %+v", ts)
	case 1:
		return infos[0], nil
	default:
		return nil, fmt.Errorf("multiple types, cannot extract single structInfo for types: %+v", ts)
	}
}

func dotConcat(x, y string) string {
	dot := ""
	if x != "" && y != "" {
		dot = "."
	}
	return x + dot + y
}

func _memberOffsets(members []btf.Member, offsets map[string]uint32, currOffset uint32, prefix string) {
	anonUnions := 0
	anonStructs := 0

	for _, member := range members {
		memberName := member.Name
		if memberName == "" {
			if _, ok := member.Type.(*btf.Union); ok {
				memberName = fmt.Sprintf("$union%d", anonUnions)
				anonUnions++
			} else if _, ok := member.Type.(*btf.Struct); ok {
				memberName = fmt.Sprintf("$struct%d", anonStructs)
				anonStructs++
			}
		}

		fullName := dotConcat(prefix, memberName)
		offset := uint32(member.Offset.Bytes())
		if typ, ok := member.Type.(*btf.Union); ok {
			_memberOffsets(typ.Members, offsets, currOffset+offset, fullName)
		} else if typ, ok := member.Type.(*btf.Struct); ok {
			_memberOffsets(typ.Members, offsets, currOffset+offset, fullName)
		}
		offsets[fullName] = currOffset + offset
	}
}

func memberOffsets(members []btf.Member) map[string]uint32 {
	offsets := make(map[string]uint32, len(members))
	_memberOffsets(members, offsets, 0, "")
	return offsets
}

func check(name string, toCheck []any, structs map[string]*structInfo, checkOffsets bool) error {
	for _, i := range toCheck {
		c, found := structs[name]
		if !found {
			return fmt.Errorf("could not find C struct %s", name)
		}

		g := reflect.TypeOf(i)
		if g == nil {
			return fmt.Errorf("nil interface passed for type %s", name)
		}

		// Input type must be a struct.
		if g.Kind() != reflect.Struct {
			return fmt.Errorf("type %s is not a struct", name)
		}

		if bs, rs := binary.Size(i), int(g.Size()); bs != rs {
			return fmt.Errorf("type %s's binary.Size (%d) does not equal its unsafe.Sizeof (%d) size (struct with implicit trailing padding?)", g.Name(), bs, rs)
		}

		if c.size != uint32(g.Size()) {
			return fmt.Errorf("%s(%d) size does not match %s(%d)", g, g.Size(),
				name, c.size)
		}

		if !checkOffsets {
			continue
		}

		for i := range g.NumField() {
			fieldName := g.Field(i).Tag.Get("align")
			// Ignore fields without `align` struct tag
			if fieldName == "" {
				continue
			}
			goOffset := uint32(g.Field(i).Offset)
			if cOffset, ok := c.fieldOffsets[fieldName]; !ok {
				return fmt.Errorf("%s.%s does not match any field (should match %s.%s) [debug=%v]",
					g, g.Field(i).Name, name, fieldName, c.fieldOffsets)
			} else if goOffset != cOffset {
				return fmt.Errorf("%s.%s offset(%d) does not match %s.%s(%d) [debug=%v]",
					g, g.Field(i).Name, goOffset, name, fieldName, cOffset, c.fieldOffsets)
			}
		}
	}

	return nil
}
