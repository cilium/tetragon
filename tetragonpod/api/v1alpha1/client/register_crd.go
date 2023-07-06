package client

import (
	"context"
	"fmt"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/tetragonpod"
	"github.com/sirupsen/logrus"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var scopedLogger = logger.GetLogger()

// RegisterCRD is used to register the CustomResourceDefinition with the API server.
func RegisterCRD(client *apiextclientset.Clientset) error {
	scopedLogger.Info("Attempting to Register the TetragonPod CustomResourceDefinition with the API server...")
	err := createUpdateCRD(client, scopedLogger)
	if err != nil {
		return fmt.Errorf("unable to create the Custom Resource Definition: %w", err)
	}
	return nil
}

// GetCRD returns the CRD object.
func GetCRD(scopedLogger logrus.FieldLogger) (*apiextv1.CustomResourceDefinition, error) {
	yamlFile, err := GetPregeneratedCRD(scopedLogger)
	if err != nil {
		return nil, err
	}
	crd := &apiextv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(yamlFile, crd); err != nil {
		return nil, fmt.Errorf("error in Unmarshalling the CustomResourceDefinition object: %w", err)
	}
	return crd, nil
}

// GetPregeneratedCRD reads the YAML File for the CustomResourceDefinition and returns an array of byte and error (if any).
func GetPregeneratedCRD(scopedLogger logrus.FieldLogger) ([]byte, error) {
	scopedLogger.Info("Getting the pre-generated Custom Resource Definitions")
	yamlFile, err := tetragonpod.GetFS().ReadFile("config/crd/bases/cilium.io_tetragonpods.yaml")
	if err != nil {
		return nil, fmt.Errorf("unable to Read the Tetragonpods YAML file: %w", err)
	}
	return yamlFile, nil
}

// createUpdateCRD is used to create if the CRD doesn't already exist.
func createUpdateCRD(client *apiextclientset.Clientset, scopedLogger logrus.FieldLogger) error {
	scopedLogger.Info("Checking if the CustomResourceDefinition already exists...")
	crd, err := GetCRD(scopedLogger)
	if err != nil {
		return err
	}
	clusterCRD, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(context.TODO(), crd.ObjectMeta.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		// The CRD does not exist already, create a new one.
		scopedLogger.Info("CustomResourceDefinition doesn't already exist, creating new...")
		err := createCRD(client, crd, scopedLogger)
		return err
	}
	if err != nil {
		return err
	}
	// I still need to handle the CRD update logic.
	scopedLogger.Infof("The CustomResourceDefinition already exists")
	_ = clusterCRD // just a temporary fix for the "variable not used" error, This will be fixed when update logic is written.
	return nil
}

// Create the new Custom resource Definition.
func createCRD(client *apiextclientset.Clientset, crd *apiextv1.CustomResourceDefinition, scopedLogger logrus.FieldLogger) error {
	scopedLogger.Infof("Creating the CustomResourceDefinition ...")
	_, err := client.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error in creating the CRD using API client: %w", err)
	}
	return nil
}
