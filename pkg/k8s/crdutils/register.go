// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package crdutils

import (
	"context"
	goerrors "errors"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
	"golang.org/x/sync/errgroup"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	v1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	v1beta1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/yaml"

	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	k8sversion "github.com/cilium/tetragon/pkg/k8s/version"
	"github.com/sirupsen/logrus"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"

	// CustomResourceDefinitionSchemaVersionKey is key to label which holds the CRD schema version
	CustomResourceDefinitionSchemaVersionKey = ciliumio.GroupName + ".k8s.crd.schema.version"
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)

	comparableCRDSchemaVersion = versioncheck.MustVersion(v1alpha1.CustomResourceDefinitionSchemaVersion)
)

// CRDOptions are options for CRD registration
type CRDOptions struct {
	ForceUpdate bool
}

type CRD struct {
	Definition apiextensionsv1.CustomResourceDefinition
	CRDName    string
	ResName    string
}

func NewCRDBytes(crdName, resName string, crdBytes []byte) CRD {
	isoCRD := apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(crdBytes, &isoCRD); err != nil {
		log.WithField("crdName", crdName).WithError(err).Fatal("Error unmarshalling pre-generated CRD")
	}

	return NewCRD(crdName, resName, isoCRD)
}

func NewCRD(crdName, resName string, crd apiextensionsv1.CustomResourceDefinition) CRD {
	return CRD{
		Definition: crd,
		CRDName:    crdName,
		ResName:    resName,
	}
}

func RegisterCRDs(clientset apiextensionsclient.Interface, crds []CRD) error {
	return RegisterCRDsWithOptions(clientset, crds, CRDOptions{})
}

func RegisterCRDsWithOptions(clientset apiextensionsclient.Interface, crds []CRD, opts CRDOptions) error {
	g, _ := errgroup.WithContext(context.Background())
	g.Go(func() error {
		return createCRDs(clientset, crds, opts)
	})

	return g.Wait()
}

// createCRDs creates or updates the CRDs with the API server.
func createCRDs(clientset apiextensionsclient.Interface, crds []CRD, opts CRDOptions) error {
	doCreateCRD := func(crd *CRD) error {
		err := createUpdateCRD(
			clientset,
			crd.CRDName,
			constructV1CRD(crd.ResName, crd.Definition),
			newDefaultPoller(),
			opts)
		if err != nil {
			err = fmt.Errorf("failed to create %s: %w", crd.CRDName, err)
			return err
		}
		return nil
	}

	var ret error
	for i := range crds {
		ret = goerrors.Join(ret, doCreateCRD(&crds[i]))
	}
	return ret
}

// createUpdateCRD ensures the CRD object is installed into the K8s cluster. It
// will create or update the CRD and its validation schema as necessary. This
// function only accepts v1 CRD objects, and defers to its v1beta1 variant if
// the cluster only supports v1beta1 CRDs. This allows us to convert all our
// CRDs into v1 form and only perform conversions on-demand, simplifying the
// code.
func createUpdateCRD(
	clientset apiextensionsclient.Interface,
	crdName string,
	crd *apiextensionsv1.CustomResourceDefinition,
	poller poller,
	opts CRDOptions,
) error {
	scopedLog := log.WithField("name", crdName)

	if !k8sversion.Capabilities().APIExtensionsV1CRD {
		log.Infof("K8s apiserver does not support v1 CRDs, falling back to v1beta1")

		return createUpdateV1beta1CRD(
			scopedLog,
			clientset.ApiextensionsV1beta1(),
			crdName,
			crd,
			poller,
			opts,
		)
	}

	v1CRDClient := clientset.ApiextensionsV1()
	// get the CRD if it is already registered.
	clusterCRD, err := v1CRDClient.CustomResourceDefinitions().Get(
		context.TODO(),
		crd.ObjectMeta.Name,
		metav1.GetOptions{})
	// If not found, register the CRD.
	if errors.IsNotFound(err) {
		scopedLog.Info("Creating CRD (CustomResourceDefinition)...")

		clusterCRD, err = v1CRDClient.CustomResourceDefinitions().Create(
			context.TODO(),
			crd,
			metav1.CreateOptions{})
		// This occurs when multiple agents race to create the CRD. Since another has
		// created it, it will also update it, hence the non-error return.
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	// some other error occurred while getting the CRD from the API server.
	if err != nil {
		return err
	}

	// CRD already registered, update it with the new version.
	if err := updateV1CRD(scopedLog, crd, clusterCRD, v1CRDClient, poller, opts); err != nil {
		return err
	}
	if err := waitForV1CRD(scopedLog, crdName, clusterCRD, v1CRDClient, poller); err != nil {
		return err
	}

	scopedLog.Info("CRD (CustomResourceDefinition) is installed and up-to-date")

	return nil
}

// constructV1CRD creates the CRD to be registered.
func constructV1CRD(
	name string,
	template apiextensionsv1.CustomResourceDefinition,
) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				CustomResourceDefinitionSchemaVersionKey: v1alpha1.CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: ciliumio.GroupName,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:       template.Spec.Names.Kind,
				Plural:     template.Spec.Names.Plural,
				ShortNames: template.Spec.Names.ShortNames,
				Singular:   template.Spec.Names.Singular,
				Categories: template.Spec.Names.Categories,
			},
			Scope:    template.Spec.Scope,
			Versions: template.Spec.Versions,
		},
	}
}

// needsUpdateV1 returns true if the CRD needs to be updated, in next cases:
// - ForceUpdate is set.
// - CRD does not have a Schema.
// - CRD does not have labels, equal to the Schema Version Key.
// - Schema Version Key of the CRD has changed.
func needsUpdateV1(clusterCRD *apiextensionsv1.CustomResourceDefinition, opts CRDOptions) bool {

	if opts.ForceUpdate {
		return true
	}

	if clusterCRD.Spec.Versions[0].Schema == nil {
		// no validation detected
		return true
	}
	v, ok := clusterCRD.Labels[CustomResourceDefinitionSchemaVersionKey]
	if !ok {
		// no schema version detected
		return true
	}

	clusterVersion, err := versioncheck.Version(v)
	if err != nil || clusterVersion.LT(comparableCRDSchemaVersion) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}

	return false
}

// updateV1CRD checks and updates the pre-existing CRD with the new one.
func updateV1CRD(
	scopedLog *logrus.Entry,
	crd, clusterCRD *apiextensionsv1.CustomResourceDefinition,
	client v1client.CustomResourceDefinitionsGetter,
	poller poller,
	opts CRDOptions,
) error {
	scopedLog.Debug("Checking if CRD (CustomResourceDefinition) needs update...")

	if crd.Spec.Versions[0].Schema != nil && needsUpdateV1(clusterCRD, opts) {
		scopedLog.Info("Updating CRD (CustomResourceDefinition)...")

		// Update the CRD with the validation schema.
		err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
			var err error
			clusterCRD, err = client.CustomResourceDefinitions().Get(
				context.TODO(),
				crd.ObjectMeta.Name,
				metav1.GetOptions{})
			if err != nil {
				return false, err
			}

			// This seems too permissive, but we only get here if the version is
			// different per needsUpdate above. If so, we want to update on any
			// validation change including adding or removing validation.
			if needsUpdateV1(clusterCRD, opts) {
				scopedLog.Debug("CRD validation is different, updating it...")

				clusterCRD.ObjectMeta.Labels = crd.ObjectMeta.Labels
				clusterCRD.Spec = crd.Spec

				// Even though v1 CRDs omit this field by default (which also
				// means it's false) it is still carried over from the previous
				// CRD. Therefore, we must set this to false explicitly because
				// the apiserver will carry over the old value (true).
				clusterCRD.Spec.PreserveUnknownFields = false

				_, err := client.CustomResourceDefinitions().Update(
					context.TODO(),
					clusterCRD,
					metav1.UpdateOptions{})
				switch {
				case errors.IsConflict(err): // Occurs as Operators race to update CRDs.
					scopedLog.WithError(err).
						Debug("The CRD update was based on an older version, retrying...")
					return false, nil
				case err == nil:
					return true, nil
				}

				scopedLog.WithError(err).Debug("Unable to update CRD validation")

				return false, err
			}

			return true, nil
		})
		if err != nil {
			scopedLog.WithError(err).Error("Unable to update CRD")
			return err
		}
	}

	return nil
}

func waitForV1CRD(
	scopedLog *logrus.Entry,
	crdName string,
	crd *apiextensionsv1.CustomResourceDefinition,
	client v1client.CustomResourceDefinitionsGetter,
	poller poller,
) error {
	scopedLog.Debug("Waiting for CRD (CustomResourceDefinition) to be available...")

	err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1.Established:
				if cond.Status == apiextensionsv1.ConditionTrue {
					return true, nil
				}
			case apiextensionsv1.NamesAccepted:
				if cond.Status == apiextensionsv1.ConditionFalse {
					err := goerrors.New(cond.Reason)
					scopedLog.WithError(err).Error("Name conflict for CRD")
					return false, err
				}
			}
		}

		var err error
		if crd, err = client.CustomResourceDefinitions().Get(
			context.TODO(),
			crd.ObjectMeta.Name,
			metav1.GetOptions{}); err != nil {
			return false, err
		}
		return false, err
	})
	if err != nil {
		return fmt.Errorf("error occurred waiting for CRD: %w", err)
	}

	return nil
}

// poller is an interface that abstracts the polling logic when dealing with
// CRD changes / updates to the apiserver. The reason this exists is mainly for
// unit-testing.
type poller interface {
	Poll(interval, duration time.Duration, conditionFn func() (bool, error)) error
}

func newDefaultPoller() defaultPoll {
	return defaultPoll{}
}

type defaultPoll struct{}

func (p defaultPoll) Poll(
	interval, duration time.Duration,
	conditionFn func() (bool, error),
) error {
	return wait.Poll(interval, duration, conditionFn)
}

func createUpdateV1beta1CRD(
	scopedLog *logrus.Entry,
	client v1beta1client.CustomResourceDefinitionsGetter,
	crdName string,
	crd *apiextensionsv1.CustomResourceDefinition,
	poller poller,
	opts CRDOptions,
) error {
	v1beta1CRD, err := convertToV1Beta1CRD(crd)
	if err != nil {
		return err
	}

	clusterCRD, err := client.CustomResourceDefinitions().Get(
		context.TODO(),
		v1beta1CRD.ObjectMeta.Name,
		metav1.GetOptions{})
	if errors.IsNotFound(err) {
		scopedLog.Info("Creating CRD (CustomResourceDefinition)...")

		clusterCRD, err = client.CustomResourceDefinitions().Create(
			context.TODO(),
			v1beta1CRD,
			metav1.CreateOptions{})
		// This occurs when multiple agents race to create the CRD. Since another has
		// created it, it will also update it, hence the non-error return.
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	if err != nil {
		return err
	}

	if err := updateV1beta1CRD(scopedLog, v1beta1CRD, clusterCRD, client, poller, opts); err != nil {
		return err
	}
	if err := waitForV1beta1CRD(scopedLog, crdName, clusterCRD, client, poller); err != nil {
		return err
	}

	scopedLog.Info("CRD (CustomResourceDefinition) is installed and up-to-date")

	return nil
}

func needsUpdateV1beta1(clusterCRD *apiextensionsv1beta1.CustomResourceDefinition, opts CRDOptions) bool {

	if opts.ForceUpdate {
		return true
	}

	if clusterCRD.Spec.Validation == nil {
		// no validation detected
		return true
	}
	v, ok := clusterCRD.Labels[CustomResourceDefinitionSchemaVersionKey]
	if !ok {
		// no schema version detected
		return true
	}

	clusterVersion, err := versioncheck.Version(v)
	if err != nil || clusterVersion.LT(comparableCRDSchemaVersion) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}

	return false
}

func convertToV1Beta1CRD(crd *apiextensionsv1.CustomResourceDefinition) (*apiextensionsv1beta1.CustomResourceDefinition, error) {
	internalCRD := new(apiextensions.CustomResourceDefinition)
	v1beta1CRD := new(apiextensionsv1beta1.CustomResourceDefinition)

	if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
		crd,
		internalCRD,
		nil,
	); err != nil {
		return nil, fmt.Errorf("unable to convert v1 CRD to internal representation: %v", err)
	}

	if err := apiextensionsv1beta1.Convert_apiextensions_CustomResourceDefinition_To_v1beta1_CustomResourceDefinition(
		internalCRD,
		v1beta1CRD,
		nil,
	); err != nil {
		return nil, fmt.Errorf("unable to convert internally represented CRD to v1beta1: %v", err)
	}

	return v1beta1CRD, nil
}

func updateV1beta1CRD(
	scopedLog *logrus.Entry,
	crd, clusterCRD *apiextensionsv1beta1.CustomResourceDefinition,
	client v1beta1client.CustomResourceDefinitionsGetter,
	poller poller,
	opts CRDOptions,
) error {
	scopedLog.Debug("Checking if CRD (CustomResourceDefinition) needs update...")

	if crd.Spec.Validation != nil && needsUpdateV1beta1(clusterCRD, opts) {
		scopedLog.Info("Updating CRD (CustomResourceDefinition)...")

		// Update the CRD with the validation schema.
		err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
			var err error
			if clusterCRD, err = client.CustomResourceDefinitions().Get(
				context.TODO(),
				crd.ObjectMeta.Name,
				metav1.GetOptions{},
			); err != nil {
				return false, err
			}

			// This seems too permissive but we only get here if the version is
			// different per needsUpdate above. If so, we want to update on any
			// validation change including adding or removing validation.
			if needsUpdateV1beta1(clusterCRD, opts) {
				scopedLog.Debug("CRD validation is different, updating it...")

				clusterCRD.ObjectMeta.Labels = crd.ObjectMeta.Labels
				clusterCRD.Spec = crd.Spec

				_, err := client.CustomResourceDefinitions().Update(
					context.TODO(),
					clusterCRD,
					metav1.UpdateOptions{})
				if err == nil {
					return true, nil
				}

				scopedLog.WithError(err).Debug("Unable to update CRD validation")

				return false, err
			}

			return true, nil
		})
		if err != nil {
			scopedLog.WithError(err).Error("Unable to update CRD")
			return err
		}
	}

	return nil
}

func waitForV1beta1CRD(
	scopedLog *logrus.Entry,
	crdName string,
	crd *apiextensionsv1beta1.CustomResourceDefinition,
	client v1beta1client.CustomResourceDefinitionsGetter,
	poller poller,
) error {
	scopedLog.Debug("Waiting for CRD (CustomResourceDefinition) to be available...")

	err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1beta1.Established:
				if cond.Status == apiextensionsv1beta1.ConditionTrue {
					return true, nil
				}
			case apiextensionsv1beta1.NamesAccepted:
				if cond.Status == apiextensionsv1beta1.ConditionFalse {
					err := goerrors.New(cond.Reason)
					scopedLog.WithError(err).Error("Name conflict for CRD")
					return false, err
				}
			}
		}

		var err error
		if crd, err = client.CustomResourceDefinitions().Get(
			context.TODO(),
			crd.ObjectMeta.Name,
			metav1.GetOptions{}); err != nil {
			return false, err
		}
		return false, err
	})
	if err != nil {
		return fmt.Errorf("error occurred waiting for CRD: %w", err)
	}

	return nil
}
