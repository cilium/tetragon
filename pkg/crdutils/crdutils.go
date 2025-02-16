// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package crdutils provides utilities for working with CRDs outside of
// Kubernetes context. It allows to load CRD objects from YAML files, apply
// defaults and validate them using the CRD's schema.
package crdutils

import (
	"errors"
	"fmt"
	"os"
	"reflect"

	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apischema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	structurallisttype "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/listtype"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"
)

type CRDObject interface {
	// don't confuse with func GetObjectMeta() metav1.Object defined by k8s apimachinery
	GetObjectMetaStruct() *metav1.ObjectMeta
}

// CRDContext holds structs necessary to default and validate a particular CRD.
// The type parameter P must be a pointer to a struct representing the CRD.
// It doesn't currently support CRD versioning.
type CRDContext[P CRDObject] struct {
	crd              *extv1.CustomResourceDefinition
	structuralSchema *apischema.Structural
	validator        validation.SchemaValidator
}

// NewCRDContext creates a new CRDContext from extv1.CustomResourceDefinition.
func NewCRDContext[P CRDObject](crd *extv1.CustomResourceDefinition) (*CRDContext[P], error) {
	var internal ext.CustomResourceDefinition
	if err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
		crd, &internal, nil,
	); err != nil {
		return nil, fmt.Errorf("failed to convert CRD: %w", err)
	}

	structural, err := apischema.NewStructural(internal.Spec.Validation.OpenAPIV3Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to create structural schema: %w", err)
	}

	validator, _, err := validation.NewSchemaValidator(internal.Spec.Validation.OpenAPIV3Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to create schema validator: %w", err)
	}

	return &CRDContext[P]{
		crd:              crd,
		structuralSchema: structural,
		validator:        validator,
	}, nil
}

func (c *CRDContext[P]) IsNamespaced() bool {
	return c.crd.Spec.Scope == extv1.NamespaceScoped
}

// ApplyDefaults applies default values to an unstructured object using the
// provided structural schema. It uses internal k8s api server machinery and
// can only process unstructured objects, so it requires to unmarshal and
// marshal again.
func (c *CRDContext[P]) ApplyDefaults(data []byte) ([]byte, unstructured.Unstructured, error) {
	// unmarshal YAML into an unstructured object
	var unstr unstructured.Unstructured
	err := yaml.UnmarshalStrict([]byte(data), &unstr)
	if err != nil {
		return nil, unstr, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	// apply defaults
	structuraldefaulting.Default(unstr.Object, c.structuralSchema)

	// marshal the defaulted object to JSON
	jsonData, err := unstr.MarshalJSON()
	if err != nil {
		return nil, unstr, fmt.Errorf("failed to marshal defaulted object: %w", err)
	}

	return jsonData, unstr, nil
}

// Validate validates an object using the CRD's schema validator and standard
// metadata and lists validations.
func (c *CRDContext[P]) Validate(obj CRDObject, unstr *unstructured.Unstructured) error {
	// validate meta
	metaErrs := apivalidation.ValidateObjectMeta(
		obj.GetObjectMetaStruct(),
		c.IsNamespaced(),
		apivalidation.NameIsDNSSubdomain,
		field.NewPath("metadata"),
	)

	// validate spec
	validationResult := c.validator.Validate(obj)
	// validate lists
	listErrs := structurallisttype.ValidateListSetsAndMaps(
		nil,
		c.structuralSchema,
		unstr.Object,
	)

	// merge errors
	var errs []error
	for _, err := range metaErrs {
		errs = append(errs, err)
	}
	errs = append(errs, validationResult.Errors...)
	for _, err := range listErrs {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// FromYAML loads a CRD object from a YAML string, applies defaults and
// validations, and returns a typed object.
func (c *CRDContext[P]) FromYAML(data string) (P, error) {
	var cr P

	// apply defaults
	jsonData, unstr, err := c.ApplyDefaults([]byte(data))
	if err != nil {
		return cr, fmt.Errorf("failed to apply defaults: %w", err)
	}

	// allocate a new instance of the underlying struct and unmarshal into it
	cr = reflect.New(reflect.TypeOf(cr).Elem()).Interface().(P)
	err = yaml.UnmarshalStrict(jsonData, cr)
	if err != nil {
		return cr, fmt.Errorf("failed to unmarshal into typed object: %w", err)
	}

	// validate
	err = c.Validate(cr, &unstr)
	if err != nil {
		return cr, fmt.Errorf("validation failed: %w", err)
	}

	return cr, nil
}

// FromFile loads a CRD object from a YAML file at the given path.
func (c *CRDContext[P]) FromFile(path string) (P, error) {
	var cr P
	data, err := os.ReadFile(path)
	if err != nil {
		return cr, fmt.Errorf("failed to read YAML from file: %w", err)
	}
	return c.FromYAML(string(data))
}
