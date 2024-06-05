package runtimesecuritypolicy

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apischema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kube-openapi/pkg/validation/validate"
	"sigs.k8s.io/yaml"
)

type validatorMap = map[schema.GroupVersionKind]validation.SchemaValidator

var getStructuralRuntimeSecurityPolicy func() (*apischema.Structural, error) = sync.OnceValues(
	func() (*apischema.Structural, error) {
		var crdRuntimeSecurityPolicy ext.CustomResourceDefinition
		err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
			&client.RuntimeSecurityPolicyCRD.Definition,
			&crdRuntimeSecurityPolicy,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to convert RuntimeSecurityPolicy CRD: %w", err)
		}
		structural, err := apischema.NewStructural(crdRuntimeSecurityPolicy.Spec.Validation.OpenAPIV3Schema)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize structural for RuntimeSecurityPolicy: %w", err)
		}
		return structural, nil
	},
)

var getValidators func() (validatorMap, error) = sync.OnceValues(
	func() (validatorMap, error) {
		ret := make(validatorMap)

		crds := []*extv1.CustomResourceDefinition{
			&client.RuntimeSecurityPolicyCRD.Definition,
		}

		for _, crd := range crds {
			for _, ver := range crd.Spec.Versions {
				internalVer := ext.CustomResourceDefinitionVersion{}
				extv1.Convert_v1_CustomResourceDefinitionVersion_To_apiextensions_CustomResourceDefinitionVersion(&ver, &internalVer, nil)
				validator, _, err := validation.NewSchemaValidator(internalVer.Schema.OpenAPIV3Schema)
				if err != nil {
					return nil, fmt.Errorf("failed to initialize validator: %w", err)
				}
				key := schema.GroupVersionKind{
					Version: ver.Name,
					Group:   crd.Spec.Group,
					Kind:    crd.Spec.Names.Kind,
				}
				ret[key] = validator
			}
		}

		return ret, nil
	},
)

func FromYAML(data []byte) (*v1alpha1.RuntimeSecurityPolicy, error) {
	rawPolicy, unstructuredPolicy, err := ApplyCRDDefault(data)
	if err != nil {
		return nil, fmt.Errorf("error applying CRD defaults: %w", err)
	}

	var runtimeSecurityPolicy v1alpha1.RuntimeSecurityPolicy

	kind := unstructuredPolicy.GetKind()
	switch kind {
	case v1alpha1.RuntimeSecurityPolicyKindDefinition:
		err = yaml.UnmarshalStrict(rawPolicy, &runtimeSecurityPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal object with defaults: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown kind: %s", kind)
	}

	validationResult, err := ValidateCRD(runtimeSecurityPolicy)
	if err != nil {
		return nil, fmt.Errorf("validation failed on policy %s: %w", runtimeSecurityPolicy.ObjectMeta.Name, err)
	}

	if len(validationResult.Errors) > 0 {
		return nil, fmt.Errorf("validation failed: %q: %w", runtimeSecurityPolicy.ObjectMeta.Name, validationResult.AsError())
	}

	return &runtimeSecurityPolicy, nil
}

func FromYAMLToTracingPolicy(data []byte) (*RuntimeSecurityTracingPolicy, error) {
	rsp, err := FromYAML(data)
	if err != nil {
		return nil, err
	}

	return ToTracingPolicy(*rsp)
}

func ValidateCRD(policy v1alpha1.RuntimeSecurityPolicy) (*validate.Result, error) {
	metaErrors := ValidateCRDMeta(policy)

	specErrors, err := ValidateCRDSpec(policy)
	if err != nil {
		return nil, err
	}

	// combine meta and spec validation errors
	specErrors.Errors = append(metaErrors, specErrors.Errors...)
	return specErrors, nil
}

func ValidateCRDMeta(policy v1alpha1.RuntimeSecurityPolicy) []error {
	errs := []error{}
	requireNamespace := false
	// if policy.GetObjectKind().GroupVersionKind().Kind == v1alpha1.RuntimeSecurityPolicyKindDefinition {
	// 	requireNamespace = true
	// }

	errorList := apivalidation.ValidateObjectMeta(&policy.ObjectMeta, requireNamespace, apivalidation.NameIsDNSSubdomain, field.NewPath("metadata"))
	for _, err := range errorList {
		errs = append(errs, err)
	}
	return errs
}

func ValidateCRDSpec(policy v1alpha1.RuntimeSecurityPolicy) (*validate.Result, error) {
	validatorMap, err := getValidators()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize validators: %w", err)
	}

	v, ok := validatorMap[policy.GroupVersionKind()]
	if !ok {
		return nil, fmt.Errorf("could not find validator for %s", policy.GroupVersionKind().String())
	}

	return v.Validate(policy), nil
}

func ApplyCRDDefault(rawPolicy []byte) ([]byte, unstructured.Unstructured, error) {
	// unmarshall into an unstructured object
	var policyUnstr unstructured.Unstructured
	err := yaml.UnmarshalStrict(rawPolicy, &policyUnstr)
	if err != nil {
		return nil, policyUnstr, fmt.Errorf("failed to unmarshall policy: %v", err)
	}

	// apply defaults
	switch policyUnstr.GetKind() {
	case v1alpha1.RuntimeSecurityPolicyKindDefinition:
		structural, err := getStructuralRuntimeSecurityPolicy()
		if err != nil {
			return nil, policyUnstr, fmt.Errorf("failed to get structural: %w", err)
		}
		structuraldefaulting.Default(policyUnstr.Object, structural)
	default:
		return nil, policyUnstr, fmt.Errorf("default: unknown kind: %s", policyUnstr.GetKind())
	}

	// marshal defaulted unstructured object into json
	rawPolicyWithDefault, err := policyUnstr.MarshalJSON()
	if err != nil {
		return nil, policyUnstr, fmt.Errorf("failed to marshal defaulted object: %w", err)
	}

	return rawPolicyWithDefault, policyUnstr, nil
}

// validateRuntimeSecurityPolicy validates the policy and should run after the
// CRD validation step, it is assuming that the CRD validation step is already
// enforced.
func validateRuntimeSecurityPolicy(policy v1alpha1.RuntimeSecurityPolicy) error {
	// The CRD validation steps verify that oneOf [executionConfig] is set
	// because we can't use CEL (yet) to capture that executionConfig should be
	// set if and only if Type is "Execution"
	for _, rule := range policy.Spec.Rules {
		switch rule.Type {
		case "Execution":
			if rule.ExecutionConfig == nil {
				return fmt.Errorf("rule type is Execution and ExecutionConfig is nil")
			}
		}
	}

	if sel := policy.Spec.Selectors; sel != nil && sel.ExecutableSelector != nil {
		for i, mp := range sel.ExecutableSelector.MatchPaths {
			for j, value := range mp.Values {
				err := selectors.ArgStringValueMaxLength(value)
				if err != nil {
					return fmt.Errorf("invalid executable selector value matchPaths[%d].value[%d]: %w", i, j, err)
				}
			}
		}
	}

	return nil
}
