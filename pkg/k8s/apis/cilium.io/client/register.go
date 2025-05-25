// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package client

import (
	_ "embed"
	"log/slog"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	crdutils "github.com/cilium/tetragon/pkg/k8s/crdutils"
)

var (
	//go:embed crds/v1alpha1/cilium.io_tracingpolicies.yaml
	crdsv1Alpha1TracingPolicies []byte

	TracingPolicyCRD = crdutils.NewCRDBytes(
		slog.Default(),
		v1alpha1.TPCRDName,
		v1alpha1.TPName,
		crdsv1Alpha1TracingPolicies)

	//go:embed crds/v1alpha1/cilium.io_tracingpoliciesnamespaced.yaml
	crdsv1Alpha1TracingPoliciesNamespaced []byte

	TracingPolicyNamespacedCRD = crdutils.NewCRDBytes(
		slog.Default(),
		v1alpha1.TPNamespacedCRDName,
		v1alpha1.TPNamespacedName,
		crdsv1Alpha1TracingPoliciesNamespaced)

	//go:embed crds/v1alpha1/cilium.io_podinfo.yaml
	crdsv1Alpha1PodInfo []byte

	PodInfoCRD = crdutils.NewCRDBytes(
		slog.Default(),
		v1alpha1.PICRDName,
		v1alpha1.PIName,
		crdsv1Alpha1PodInfo)

	AllCRDs = []crdutils.CRD{
		TracingPolicyCRD,
		TracingPolicyNamespacedCRD,
		PodInfoCRD,
	}
)
