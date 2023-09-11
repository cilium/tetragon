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
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kube-openapi/pkg/validation/validate"
	"sigs.k8s.io/yaml"
)

var validatorState = struct {
	validators map[schema.GroupVersionKind]*validate.SchemaValidator
	init       sync.Once
	initError  error
}{
	validators: make(map[schema.GroupVersionKind]*validate.SchemaValidator),
}

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

func (gtp GenericTracingPolicy) Namespaced() bool {
	return gtp.APIVersion == v1alpha1.TPNamespacedKindDefinition
}

func FromYAML(data string) (TracingPolicy, error) {
	var k GenericTracingPolicy

	err := yaml.UnmarshalStrict([]byte(data), &k)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling the policy: %w", err)
	}

	validationResult, err := ValidateCRD(k)
	if err != nil {
		return nil, err
	}

	// display all validation errors and warnings before maybe returning a validation error
	for _, e := range validationResult.Errors {
		logger.GetLogger().WithFields(logrus.Fields{
			"kind":    k.Kind,
			"version": k.APIVersion,
			"name":    k.TpName(),
		}).WithError(e).Error("Validation error")
	}
	for _, e := range validationResult.Warnings {
		logger.GetLogger().WithFields(logrus.Fields{
			"kind":    k.Kind,
			"version": k.APIVersion,
			"name":    k.TpName(),
		}).WithError(e).Warn("Validation warning")
	}
	fmt.Println("HEY", k.Spec.KProbes[0].Syscall)
	if len(validationResult.Errors) > 0 {
		return nil, fmt.Errorf("validation failed: %w", validationResult.AsError())
	}

	return &k, nil
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
