package tracing

import (
	"fmt"
	"strings"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/btf"

	_btf "github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func buildBtfArg(arg v1alpha1.KProbeArg, btfArg *[api.MaxBtfArgDepth]api.ConfigBtfArg) (*_btf.Type, error) {
	spec, err := btf.NewBTF()
	if err != nil {
		return nil, fmt.Errorf("Unable to load BTF file with error : %v", err)
	}

	partialPath := strings.Split(arg.ExtractParam, ".")
	if len(partialPath) > api.MaxBtfArgDepth {
		return nil, fmt.Errorf("Exausted research in BTF for type %s. The maximum depth allowed is %d", arg.Type, api.MaxBtfArgDepth)
	}

	rootType, err := spec.AnyTypeByName(arg.Type)
	if err != nil {
		return nil, fmt.Errorf("Type %s has not been found in BTF", arg.Type)
	}
	lastBtfType, err := btf.FindNextBTFType(btfArg, rootType, &partialPath, 0)
	if err != nil {
		return nil, err
	}
	return lastBtfType, nil
}
