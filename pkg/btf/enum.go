package btf

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf/btf"
)

type enum struct {
	values map[string]uint64
}

var (
	enums       map[string]*enum
	initialize  sync.Once
	initialized bool
)

func getEnum(name string) *enum {
	var en *enum
	var ok bool

	if name == "" {
		return nil
	}
	if en, ok = enums[name]; ok {
		return en
	}
	en = &enum{}
	en.values = make(map[string]uint64)
	enums[name] = en
	return en
}

func setup(spec *btf.Spec) {
	enums = make(map[string]*enum)
	all := getEnum("all")

	iter := spec.Iterate()
	for iter.Next() {
		enumBtf, ok := iter.Type.(*btf.Enum)
		if !ok {
			continue
		}

		en := getEnum(enumBtf.Name)

		for _, v := range enumBtf.Values {
			if en != nil {
				en.values[v.Name] = v.Value
			}
			all.values[v.Name] = v.Value
		}
	}

	if false {
		for name, en := range enums {
			fmt.Printf("%s\n", name)
			for n, v := range en.values {
				fmt.Printf("  %s -> %d\n", n, v)
			}
		}
	}

	initialized = true
}

func InitEnumMap(spec *btf.Spec) {
	initialize.Do(func() { setup(spec) })
}

func findByName(name string, val string) (uint64, error) {
	if !initialized {
		return 0, fmt.Errorf("not initialized")
	}

	if en, ok := enums[name]; ok {
		if v, ok := en.values[val]; ok {
			return v, nil
		}
	}

	return 0, fmt.Errorf("not found")
}

func EnumFind(val string) (uint64, error) {
	return findByName("all", val)
}

func EnumFindByName(name string, val string) (uint64, error) {
	return findByName(name, val)
}

func EnumFindByValue(name string, val uint64) (string, error) {
	if !initialized {
		return "", fmt.Errorf("not initialized")
	}

	if en, ok := enums[name]; ok {
		for n, v := range en.values {
			if val == v {
				return n, nil
			}
		}
	}

	return "", fmt.Errorf("not found")

}
