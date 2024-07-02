// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package client

import (
	_ "embed"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	crdutils "github.com/cilium/tetragon/pkg/k8s/crdutils"
)

var (
	//go:embed crds/v1alpha1/cilium.io_tracingpolicies.yaml
	crdsv1Alpha1TracingPolicies []byte

	TracingPolicyCRD = crdutils.NewCRDBytes(
		v1alpha1.TPCRDName,
		v1alpha1.TPName,
		crdsv1Alpha1TracingPolicies)

	//go:embed crds/v1alpha1/cilium.io_tracingpoliciesnamespaced.yaml
	crdsv1Alpha1TracingPoliciesNamespaced []byte

	TracingPolicyNamespacedCRD = crdutils.NewCRDBytes(
		v1alpha1.TPNamespacedCRDName,
		v1alpha1.TPNamespacedName,
		crdsv1Alpha1TracingPoliciesNamespaced)

	//go:embed crds/v1alpha1/cilium.io_podinfo.yaml
	crdsv1Alpha1PodInfo []byte

	PodInfoCRD = crdutils.NewCRDBytes(
		v1alpha1.PICRDName,
		v1alpha1.PIName,
		crdsv1Alpha1PodInfo)

	//go:embed crds/v1alpha1/cilium.io_runtimesecuritypolicies.yaml
	crdsv1Alpha1RuntimeSecurityPolicies []byte

	RuntimeSecurityPolicyCRD = crdutils.NewCRDBytes(
		v1alpha1.RuntimeSecurityPolicyCRDName,
		v1alpha1.RuntimeSecurityPolicyName,
		crdsv1Alpha1RuntimeSecurityPolicies,
	)

	AllCRDs = []crdutils.CRD{
		TracingPolicyCRD,
		TracingPolicyNamespacedCRD,
		PodInfoCRD,
		RuntimeSecurityPolicyCRD,
	}
)
