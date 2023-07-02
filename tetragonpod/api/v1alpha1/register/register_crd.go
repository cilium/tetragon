package register

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/tetragonpod"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var scopedLogger = logger.GetLogger()

// GetCRD returns the CRD object.
func GetCRD() *apiextv1.CustomResourceDefinition {
	yamlFile := GetPregeneratedCRD()
	crd := &apiextv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(yamlFile, crd); err != nil {
		scopedLogger.Fatalf("failed to unmarshal CRD: %v", err)
	}
	return crd
}

// get the pregenerated YAML file of the CRD.
func GetPregeneratedCRD() []byte {
	yamlFile, err := tetragonpod.GetFS().ReadFile("config/crd/bases/cilium.io.tetragon.cilium.io_tetragonpods.yaml")
	if err != nil {
		scopedLogger.Fatalf("failed to read CRD YAML file: %v", err)
	}
	return yamlFile
}
