package main

import (
	"fmt"
	"go/ast"
	"log"
	"os"
	"os/exec"
	"reflect"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	fuzz "github.com/google/gofuzz"

	lru "github.com/hashicorp/golang-lru/v2"
	crdmarkers "sigs.k8s.io/controller-tools/pkg/crd/markers"
	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
	"sigs.k8s.io/yaml"
)

var enumCache *lru.Cache[string, []string]

func EnumValues(structure interface{}, fieldName string) ([]string, error) {
	// no cache
	if enumCache == nil {
		var err error
		enumCache, err = lru.New[string, []string](1024)
		if err != nil {
			return nil, err
		}
		return enumValues(structure, fieldName)
	}

	structureType := reflect.TypeOf(structure)
	key := structureType.Name() + fieldName

	// cache hit
	if ret, ok := enumCache.Get(key); ok {
		return ret, nil
	}

	// cache miss
	value, err := enumValues(structure, fieldName)
	enumCache.Add(key, value)
	return value, err
}

func enumValues(structure interface{}, fieldName string) ([]string, error) {
	structureType := reflect.TypeOf(structure)

	reg := &markers.Registry{}
	err := crdmarkers.Register(reg)
	if err != nil {
		return nil, err
	}
	c := &markers.Collector{}
	c.Registry = reg

	packages, err := loader.LoadRoots(structureType.PkgPath())
	if err != nil {
		return nil, err
	}

	if len(packages) != 1 {
		// it's not supposed to happen since PkgPath() should return only one
		// pkg and LoadRoots should at least return one pkg
		panic(err)
	}
	pack := packages[0]

	pack.NeedSyntax() // this is needed to load the AST if we don't call MarkersInPackage
	m, err := c.MarkersInPackage(pack)
	if err != nil {
		panic(err)
	}

	var out []string

	for _, file := range pack.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok {
				if st, ok := ts.Type.(*ast.StructType); ok && (ts.Name.Name == structureType.Name()) {
					for _, field := range st.Fields.List {
						if len(field.Names) == 0 {
							continue // it's an embedded struct
						}
						if field.Names[0].Name == fieldName {
							// this is a typing system mess
							enum := m[field]["kubebuilder:validation:Enum"]
							if len(enum) > 0 {
								e := enum[0].(crdmarkers.Enum)
								for _, value := range e {
									out = append(out, value.(string))
								}
							}
						}
					}
				} else {
					// if we found the wrong struct, let's stop here
					return false
				}
			}
			// we might investigate a lot of useless nodes
			return true
		})
	}
	return out, nil
}

func main() {
	// fetch data needed to initialize fuzzer
	log.Println("Loading symbols...")
	ksymbols, err := ksyms.NewKsyms("/proc")
	if err != nil {
		panic(err)
	}
	// we can do this rootless because we only need the names but let's fix that later
	functionNames := ksymbols.FunctionNames()
	log.Println("Symbols loaded!")

	// initialize fuzzer
	fuzzer := createKprobeSpecFuzzer(functionNames)

	// generate a possible tracing policy
	var tracingPolicy v1alpha1.KProbeSpec
	fuzzer.Fuzz(&tracingPolicy)
	fmt.Printf("%#v\n", tracingPolicy)
	tp := tracingpolicy.GenericTracingPolicy{
		ApiVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: tracingpolicy.Metadata{
			Name: "fuzz",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{tracingPolicy},
		},
	}

	tpByte, err := yaml.Marshal(tp)
	if err != nil {
		panic(err)
	}
	os.WriteFile("fuzz.yaml", tpByte, 0644)

	// load the tracing policy
	output, err := exec.Command("sudo", "../../tetragon", "--bpf-lib", "../../bpf/objs", "--tracing-policy", "fuzz.yaml").Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			fmt.Println(string(e.Stderr))
		}
		fmt.Println(err)
	}
	fmt.Println(output)

	// see if that made tetragon crash, log that policy if yes

}

type KprobeSpecFuzzer struct {
	fuzzer *fuzz.Fuzzer
}

func NewKprobeSpecFuzzer() *KprobeSpecFuzzer {
	ksymbols, err := ksyms.NewKsyms("/proc")
	if err != nil {
		panic(err)
	}
	// we can do this rootless because we only need the names but let's fix that later
	functionNames := ksymbols.FunctionNames()

	ksf := &KprobeSpecFuzzer{}
	// initialize fuzzer
	ksf.fuzzer = createKprobeSpecFuzzer(functionNames)
	return ksf
}

func (ksf KprobeSpecFuzzer) Generate() *v1alpha1.KProbeSpec {
	var tp v1alpha1.KProbeSpec
	ksf.fuzzer.Fuzz(&tp)
	return &tp
}

func createKprobeSpecFuzzer(functionNames []string) *fuzz.Fuzzer {
	return fuzz.New().Funcs(
		func(s *v1alpha1.KProbeSpec, c fuzz.Continue) {
			// find a random function to hook
			s.Call = functionNames[c.Intn(len(functionNames))]

			c.Fuzz(&s.Return)
			c.Fuzz(&s.Syscall)
			c.Fuzz(&s.Args)
		},
		func(a *v1alpha1.KProbeArg, c fuzz.Continue) {
			c.FuzzNoCustom(a)
			types, err := EnumValues(v1alpha1.KProbeArg{}, "Type")
			if err != nil {
				panic(err)
			}
			a.Type = types[c.Intn(len(types))]
		},
	)

}
