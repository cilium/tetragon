// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build integration

package podinfo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type ControllerTestSuite struct {
	suite.Suite
	testEnv   *envtest.Environment
	k8sClient client.Client
}

// SetupSuite creates an environment for testing the PodInfo controller with a kubernetes cluster.
func (suite *ControllerTestSuite) SetupSuite() {
	useExistingCluster := true
	suite.testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
	}
	cfg, err := suite.testEnv.Start()
	require.NoError(suite.T(), err)
	require.NoError(suite.T(), v1alpha1.AddToScheme(scheme.Scheme))
	suite.k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(suite.T(), err)
}

// TestPodInfoCreation checks if PodInfo gets created / deleted for a Pod.
func (suite *ControllerTestSuite) TestPodInfoCreateAndDelete() {
	ctx := context.Background()
	pod := getRandomPod("default")
	require.NoError(suite.T(), suite.k8sClient.Create(ctx, pod))

	podLookupKey := types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}
	assert.Eventually(suite.T(), func() bool {
		err := suite.k8sClient.Get(ctx, podLookupKey, pod)
		if err != nil {
			return false
		}
		return hasAllRequiredFields(pod)
	}, 20*time.Second, 1*time.Second)

	podInfo := &v1alpha1.PodInfo{}
	assert.Eventually(suite.T(), func() bool {
		err := suite.k8sClient.Get(ctx, podLookupKey, podInfo)
		if err != nil {
			return false
		}
		return equal(pod, podInfo)
	}, 20*time.Second, 1*time.Second)

	require.NoError(suite.T(), suite.k8sClient.Delete(ctx, pod))
	assert.Eventually(suite.T(), func() bool {
		return apierrors.IsNotFound(suite.k8sClient.Get(ctx, podLookupKey, podInfo))
	}, 20*time.Second, 1*time.Second)
}

// TestPodInfoUpdate checks if updating pod, also updates the podInfo.
func (suite *ControllerTestSuite) TestPodInfoUpdate() {
	ctx := context.Background()
	pod := getRandomPod("default")
	require.NoError(suite.T(), suite.k8sClient.Create(ctx, pod))
	podLookupKey := types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}
	assert.Eventually(suite.T(), func() bool {
		err := suite.k8sClient.Get(ctx, podLookupKey, pod)
		if err != nil {
			return false
		}
		return hasAllRequiredFields(pod)
	}, 20*time.Second, 1*time.Second)

	// wait for PodInfo to be created
	podInfo := &v1alpha1.PodInfo{}
	assert.Eventually(suite.T(), func() bool {
		err := suite.k8sClient.Get(ctx, podLookupKey, podInfo)
		if err != nil {
			return false
		}
		return equal(pod, podInfo)
	}, 20*time.Second, 1*time.Second)

	// Update the pod labels.
	pod.ObjectMeta.Labels = getRandMap()
	require.NoError(suite.T(), suite.k8sClient.Update(ctx, pod))

	// Get the updated podInfo
	assert.Eventually(suite.T(), func() bool {
		updatedPodInfo := &v1alpha1.PodInfo{}
		err := suite.k8sClient.Get(ctx, podLookupKey, updatedPodInfo)
		if err != nil {
			return false
		}
		return equal(pod, updatedPodInfo)
	}, 20*time.Second, 1*time.Second)
}

// getRandomPod returns a kubernetes pod.
func getRandomPod(namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("test-pod-%s", getRandString(getRandNum())),
			Namespace:   namespace,
			Labels:      getRandMap(),
			Annotations: getRandMap(),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "nginx:latest",
				},
			},
		},
	}
}

// TearDownSuite will close the test environment and close the go-routine running the controller.
func (suite *ControllerTestSuite) TearDownSuite() {
	require.NoError(suite.T(), suite.testEnv.Stop())
}

func TestControllerSuite(t *testing.T) {
	suite.Run(t, new(ControllerTestSuite))
}
