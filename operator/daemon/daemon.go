// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/k8s/version"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "tetragon-daemon")
)

func InstallTetragonDaemonSet() error {
	restConfig, err := getConfig()
	if err != nil {
		log.WithError(err).Fatal("Unable to check k8s configuration")
	}

	k8sClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.WithError(err).Fatal("Unable to create k8s client")
	}

	if err := version.UpdateK8sServerVersion(k8sClient); err != nil {
		log.WithError(err).Fatal("Unable to check k8s version")
	}

	ctx := context.Background()

	exists, err := isDaemonSetExists(ctx, k8sClient)
	if err != nil {
		return fmt.Errorf("failed to get tetragon daemon set: %s", err)
	}
	if exists {
		log.Info("tetragon daemon set already exists")
		return nil
	}

	log.Infof("installing tetragon daemon set: %s", option.Config.TetragonDaemonSetName)
	if err := createDaemonSet(ctx, k8sClient); err != nil {
		return fmt.Errorf("failed to create tetragon daemon set: %s", err)
	}

	log.Info("tetragon daemon set installation complete")
	return nil
}

func getConfig() (*rest.Config, error) {
	if option.Config.KubeCfgPath != "" {
		return clientcmd.BuildConfigFromFlags("", option.Config.KubeCfgPath)
	}
	return rest.InClusterConfig()
}

func isDaemonSetExists(ctx context.Context, client *kubernetes.Clientset) (bool, error) {
	_, err := client.AppsV1().DaemonSets(option.Config.TetragonNamespace).Get(ctx, option.Config.TetragonDaemonSetName, k8sv1.GetOptions{})
	if err != nil {
		if err, ok := err.(*k8serrors.StatusError); ok && err.Status().Code == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func createDaemonSet(_ context.Context, _ *kubernetes.Clientset) error {
	//TODO: implement me...
	return errors.New("not implemented")
}
