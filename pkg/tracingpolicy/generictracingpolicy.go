// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

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
	validators map[schema.GroupVersionKind]validation.SchemaValidator
	init       sync.Once
	initError  error
}{
	validators: make(map[schema.GroupVersionKind]validation.SchemaValidator),
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
// marshal).
// This first reading step is also used to return if the resource is namespaced
// or not (second return value).
func ApplyCRDDefault(rawPolicy []byte) (rawPolicyWithDefault []byte, namespaced bool, err error) {
	defaultState.init.Do(func() {
		// retrieve CRD
		var crvInternalTP ext.CustomResourceDefinition
		err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
			&client.TracingPolicyCRD.Definition,
			&crvInternalTP,
			nil,
		)
		if err != nil {
			defaultState.initError = fmt.Errorf("failed to convert TracingPolicy CRD: %w", err)
			return
		}

		var crvInternalTPN ext.CustomResourceDefinition
		err = extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
			&client.TracingPolicyNamespacedCRD.Definition,
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
		return nil, false, fmt.Errorf("failed to initialize default structural schemas: %w", validatorState.initError)
	}

	// unmarshall into an unstructured object
	var policyUnstr unstructured.Unstructured
	err = yaml.UnmarshalStrict(rawPolicy, &policyUnstr)
	if err != nil {
		return nil, false, fmt.Errorf("failed to unmarshall policy: %v", err)
	}

	// apply defaults
	switch policyUnstr.GetKind() {
	case v1alpha1.TPKindDefinition:
		structuraldefaulting.Default(policyUnstr.Object, defaultState.structuralSchemaTP)
	case v1alpha1.TPNamespacedKindDefinition:
		structuraldefaulting.Default(policyUnstr.Object, defaultState.structuralSchemaTPN)
		namespaced = true
	}

	// marshal defaulted unstructured object into json
	rawPolicyWithDefault, err = policyUnstr.MarshalJSON()
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal defaulted object: %w", err)
	}

	return rawPolicyWithDefault, namespaced, nil
}

// K8sTracingPolicyObject is necessary to have a common type for
// GenericTracingPolicy and GenericTracingPolicyNamespaced for the validation
// functions.
//
// NB: we could get rid of one type as they represent the same object
// internally, just keep GenericTracingPolicy and remove that interface. We can
// then distinguish between Namespaced or not by reading the Kind of the
// resource. That's a matter of preference between type casting and calling a
// method to distinguish which kind is it really.
type K8sTracingPolicyObject interface {
	TracingPolicy
	GetKind() string
	GetGroupVersionKind() schema.GroupVersionKind
	GetMetadata() k8sv1.ObjectMeta
}

func (gtp GenericTracingPolicy) GetKind() string {
	return gtp.Kind
}
func (gtp GenericTracingPolicy) GetGroupVersionKind() schema.GroupVersionKind {
	return gtp.GroupVersionKind()
}
func (gtp GenericTracingPolicy) GetMetadata() k8sv1.ObjectMeta {
	return gtp.Metadata
}

func (gtp GenericTracingPolicyNamespaced) GetKind() string {
	return gtp.Kind
}
func (gtp GenericTracingPolicyNamespaced) GetGroupVersionKind() schema.GroupVersionKind {
	return gtp.GroupVersionKind()
}
func (gtp GenericTracingPolicyNamespaced) GetMetadata() k8sv1.ObjectMeta {
	return gtp.Metadata
}

// ValidateCRD validates the metadata of the objects (name, labels,
// annotations...) and the specification using the custom CRD schemas.
func ValidateCRD(policy K8sTracingPolicyObject) (*validate.Result, error) {
	metaErrors := ValidateCRDMeta(policy)

	specErrors, err := ValidateCRDSpec(policy)
	if err != nil {
		return nil, err
	}

	// combine meta and spec validation errors
	specErrors.Errors = append(metaErrors, specErrors.Errors...)
	return specErrors, nil
}

func ValidateCRDMeta(policy K8sTracingPolicyObject) []error {
	errs := []error{}
	requireNamespace := false
	if policy.GetKind() == v1alpha1.TPNamespacedKindDefinition {
		requireNamespace = true
	}
	metadata := policy.GetMetadata()

	errorList := apivalidation.ValidateObjectMeta(&metadata, requireNamespace, apivalidation.NameIsDNSSubdomain, field.NewPath("metadata"))
	for _, err := range errorList {
		errs = append(errs, err)
	}
	return errs
}

func ValidateCRDSpec(policy K8sTracingPolicyObject) (*validate.Result, error) {
	validatorState.init.Do(func() {
		crds := []*extv1.CustomResourceDefinition{
			&client.TracingPolicyCRD.Definition,
			&client.TracingPolicyNamespacedCRD.Definition,
		}

		// initialize the validators from the CRDs
		for _, crd := range crds {
			internal := &ext.CustomResourceDefinition{}
			if err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(crd, internal, nil); err != nil {
				validatorState.initError = err
				return
			}
			for _, ver := range internal.Spec.Versions {
				var sv validation.SchemaValidator
				var err error
				if ver.Schema != nil {
					sv, _, err = validation.NewSchemaValidator(ver.Schema.OpenAPIV3Schema)
					if err != nil {
						validatorState.initError = err
						return
					}
				}
				if internal.Spec.Validation != nil {
					sv, _, err = validation.NewSchemaValidator(internal.Spec.Validation.OpenAPIV3Schema)
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

	v, ok := validatorState.validators[policy.GetGroupVersionKind()]
	if !ok {
		return nil, fmt.Errorf("could not find validator for: %s", policy.GetGroupVersionKind().String())
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
	rawPolicy, namespaced, err := ApplyCRDDefault([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("error applying CRD defaults: %w", err)
	}

	var policy K8sTracingPolicyObject
	if namespaced {
		policy = &GenericTracingPolicyNamespaced{}
	} else {
		policy = &GenericTracingPolicy{}
	}

	err = yaml.UnmarshalStrict(rawPolicy, &policy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal object with defaults: %w", err)
	}

	validationResult, err := ValidateCRD(policy)
	if err != nil {
		return nil, fmt.Errorf("validation failed %q: %w", policy.GetMetadata().Name, err)
	}

	if len(validationResult.Errors) > 0 {
		return nil, fmt.Errorf("validation failed: %q: %w", policy.GetMetadata().Name, validationResult.AsError())
	}

	return policy, nil
}

func FromFile(path string) (TracingPolicy, error) {
	policy, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tp, err := FromYAML(string(policy))
	if err != nil {
		return nil, fmt.Errorf("failed loading tracing policy file %q: %w", path, err)
	}
	return tp, nil
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
