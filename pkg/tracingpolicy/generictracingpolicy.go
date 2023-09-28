// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"

	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apischema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kube-openapi/pkg/validation/validate"
	"sigs.k8s.io/yaml"
)

// validatorState is used by the CRD validation process to store the validators
// structures.
var validatorState = struct {
	validators map[schema.GroupVersionKind]*validate.SchemaValidator
	init       sync.Once
	initError  error
}{
	validators: make(map[schema.GroupVersionKind]*validate.SchemaValidator),
}

// defaultState is used by to store the structural schemas apply the defaults in
// the custom resources.
var defaultState = struct {
	structuralSchemaTP  *apischema.Structural
	structuralSchemaTPN *apischema.Structural
	init                sync.Once
	initError           error
}{}

// ApplyCRDDefault uses internal k8s api server machinery and can only process
// unustructured objects (unfortunately, since it requires to unmarshal and
// marshal)
func ApplyCRDDefault(rawPolicy []byte) ([]byte, error) {
	defaultState.init.Do(func() {
		// retrieve CRD
		customTP := client.GetPregeneratedCRD(v1alpha1.TPCRDName)
		var crvInternalTP ext.CustomResourceDefinition
		err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
			&customTP,
			&crvInternalTP,
			nil,
		)
		if err != nil {
			defaultState.initError = fmt.Errorf("failed to convert TracingPolicy CRD: %w", err)
			return
		}

		customTPN := client.GetPregeneratedCRD(v1alpha1.TPNamespacedCRDName)
		var crvInternalTPN ext.CustomResourceDefinition
		err = extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
			&customTPN,
			&crvInternalTPN,
			nil,
		)
		if err != nil {
			defaultState.initError = fmt.Errorf("failed to convert TracingPolicyNamespaced CRD: %w", err)
			return
		}

		// create a structural schema from the CRD
		defaultState.structuralSchemaTP, err = apischema.NewStructural(crvInternalTP.Spec.Validation.OpenAPIV3Schema)
		if err != nil {
			defaultState.initError = fmt.Errorf("failed to initialize structural for TracingPolicy: %w", err)
			return
		}
		defaultState.structuralSchemaTPN, err = apischema.NewStructural(crvInternalTPN.Spec.Validation.OpenAPIV3Schema)
		if err != nil {
			defaultState.initError = fmt.Errorf("failed to initialize structural for TracingPolicyNamespaced: %w", err)
			return
		}
	})

	if defaultState.initError != nil {
		return nil, fmt.Errorf("failed to initialize default structural schemas: %w", validatorState.initError)
	}

	// unmarshall into an unstructured object
	var policyUnstr unstructured.Unstructured
	err := yaml.UnmarshalStrict(rawPolicy, &policyUnstr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall policy: %v", err)
	}

	// apply defaults
	switch policyUnstr.GetKind() {
	case v1alpha1.TPKindDefinition:
		structuraldefaulting.Default(policyUnstr.Object, defaultState.structuralSchemaTP)
	case v1alpha1.TPNamespacedKindDefinition:
		structuraldefaulting.Default(policyUnstr.Object, defaultState.structuralSchemaTPN)
	}

	// marshal defaulted unstructured object into json
	data, err := policyUnstr.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal defaulted object: %w", err)
	}

	return data, nil

}

// ValidateCRD validates the metadata of the objects (name, labels,
// annotations...) and the specification using the custom CRD schemas.
func ValidateCRD(policy GenericTracingPolicy) (*validate.Result, error) {
	metaErrors := ValidateCRDMeta(policy)

	specErrors, err := ValidateCRDSpec(policy)
	if err != nil {
		return nil, err
	}

	// combine meta and spec validation errors
	specErrors.Errors = append(metaErrors, specErrors.Errors...)
	return specErrors, nil
}

func ValidateCRDMeta(policy GenericTracingPolicy) []error {
	errs := []error{}
	errorList := apivalidation.ValidateObjectMeta(&policy.Metadata, false, apivalidation.NameIsDNSSubdomain, field.NewPath("metadata"))
	for _, err := range errorList {
		errs = append(errs, err)
	}
	return errs
}

func ValidateCRDSpec(policy GenericTracingPolicy) (*validate.Result, error) {
	validatorState.init.Do(func() {
		var crds []extv1.CustomResourceDefinition
		crds = append(crds, client.GetPregeneratedCRD(v1alpha1.TPCRDName))
		crds = append(crds, client.GetPregeneratedCRD(v1alpha1.TPNamespacedCRDName))

		// initialize the validators from the CRDs
		for _, crd := range crds {
			internal := &ext.CustomResourceDefinition{}
			if err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&crd, internal, nil); err != nil {
				validatorState.initError = err
				return
			}
			for _, ver := range internal.Spec.Versions {
				var sv *validate.SchemaValidator
				var err error
				sv, _, err = validation.NewSchemaValidator(ver.Schema)
				if err != nil {
					validatorState.initError = err
					return
				}
				if internal.Spec.Validation != nil {
					sv, _, err = validation.NewSchemaValidator(internal.Spec.Validation)
					if err != nil {
						validatorState.initError = err
						return
					}
				}
				validatorState.validators[schema.GroupVersionKind{
					Group:   internal.Spec.Group,
					Version: ver.Name,
					Kind:    internal.Spec.Names.Kind,
				}] = sv
			}
		}
	})

	if validatorState.initError != nil {
		return nil, fmt.Errorf("failed to initialize validators: %w", validatorState.initError)
	}

	v, ok := validatorState.validators[policy.GetObjectKind().GroupVersionKind()]
	if !ok {
		return nil, fmt.Errorf("could not find validator for: " + policy.GetObjectKind().GroupVersionKind().String())
	}

	return v.Validate(policy), nil
}

type GenericTracingPolicy struct {
	k8sv1.TypeMeta
	Metadata k8sv1.ObjectMeta           `json:"metadata"`
	Spec     v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicy) TpName() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicy) TpSpec() *v1alpha1.TracingPolicySpec {
	return &gtp.Spec
}

func (gtp *GenericTracingPolicy) TpInfo() string {
	return gtp.Metadata.Name
}

func FromYAML(data string) (TracingPolicy, error) {
	rawPolicy, err := ApplyCRDDefault([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("error applying CRD defaults: %w", err)
	}

	var policy GenericTracingPolicy
	err = yaml.UnmarshalStrict(rawPolicy, &policy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal object with defaults: %w", err)
	}

	validationResult, err := ValidateCRD(policy)
	if err != nil {
		return nil, err
	}

	// display all validation errors and warnings before maybe returning a validation error
	for _, e := range validationResult.Errors {
		logger.GetLogger().WithFields(logrus.Fields{
			"kind":    policy.Kind,
			"version": policy.APIVersion,
			"name":    policy.TpName(),
		}).WithError(e).Error("Validation error")
	}
	for _, e := range validationResult.Warnings {
		logger.GetLogger().WithFields(logrus.Fields{
			"kind":    policy.Kind,
			"version": policy.APIVersion,
			"name":    policy.TpName(),
		}).WithError(e).Warn("Validation warning")
	}
	if len(validationResult.Errors) > 0 {
		return nil, fmt.Errorf("validation failed: %w", validationResult.AsError())
	}

	return &policy, nil
}

func FromFile(path string) (TracingPolicy, error) {
	policy, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromYAML(string(policy))
}

type GenericTracingPolicyNamespaced struct {
	k8sv1.TypeMeta
	Metadata k8sv1.ObjectMeta           `json:"metadata"`
	Spec     v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicyNamespaced) TpNamespace() string {
	return gtp.Metadata.Namespace
}

func (gtp *GenericTracingPolicyNamespaced) TpName() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicyNamespaced) TpSpec() *v1alpha1.TracingPolicySpec {
	return &gtp.Spec
}

func (gtp *GenericTracingPolicyNamespaced) TpInfo() string {
	return gtp.Metadata.Name
}
