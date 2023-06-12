// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package crd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/version"
	version2 "github.com/cilium/tetragon/pkg/version"
	tetragonClient "github.com/cilium/tetragon/tetragonpod/api/v1alpha1/client"
	"github.com/sirupsen/logrus"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "crd")

func RegisterCRDs() {
	restConfig, err := getConfig()
	if err != nil {
		log.WithError(err).Fatal("Unable to check k8s configuration")
	}

	k8sClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.WithError(err).Fatal("Unable to create k8s client")
	}

	k8sAPIExtClient, err := clientset.NewForConfig(restConfig)
	if err != nil {
		log.WithError(err).Fatal("Unable to create k8s API ext. client")
	}

	err = version.UpdateK8sServerVersion(k8sClient)
	if err != nil {
		log.WithError(err).Fatal("Unable to check k8s version")
	}

	log.WithFields(logrus.Fields{
		"config":  fmt.Sprintf("%+v", option.Config),
		"version": version2.Version,
	}).Info("Starting Tetragon Operator")
	capabilities := version.Capabilities()
	if !capabilities.MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			version.Version(), version.MinimalVersionConstraint)
	}

	// Register the CRDs after validating that we are running on a supported
	// version of K8s.
	if !option.Config.SkipCRDCreation {
		if err := client.RegisterCRDs(k8sAPIExtClient); err != nil {
			log.WithError(err).Fatal("Unable to register CRDs")
		}
		if !option.Config.SkipTetragonPodCRD {
			log.Info("Registering the TetragonPod CRD")
			// Register TetragonPod CRD
			if err := tetragonClient.RegisterCRD(k8sAPIExtClient); err != nil {
				log.WithError(err).Fatal("Unable to register TetragonPod CRDs")
			}
		}
	} else {
		log.Info("Skipping creation of CRDs")
	}

	log.Info("Initialization complete")
}

func getConfig() (*rest.Config, error) {
	if option.Config.KubeCfgPath != "" {
		return clientcmd.BuildConfigFromFlags("", option.Config.KubeCfgPath)
	}
	return rest.InClusterConfig()
}
