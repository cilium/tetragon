// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build integration

package manager

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const (
	nodeName = "tetragon-dev-control-plane"
)

// ManagerTestSuite is a test suite for the ControllerManager. It assumes that
// a Kind cluster created with "make kind" is running. More specifically, it
// assumes that the cluster has a single node named "tetragon-dev-control-plane".
type ManagerTestSuite struct {
	suite.Suite
	testEnv *envtest.Environment
	manager *ControllerManager
}

func (suite *ManagerTestSuite) SetupSuite() {
	err := os.Setenv("NODE_NAME", nodeName)
	assert.NoError(suite.T(), err)
	node.SetKubernetesNodeName()
	useExistingCluster := true
	suite.testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
	}
	_, err = suite.testEnv.Start()
	assert.NoError(suite.T(), err)
	suite.manager = Get()
	suite.manager.Start(context.Background())
}

func (suite *ManagerTestSuite) TestListNamespaces() {
	// List namespaces.
	namespaces, err := suite.manager.ListNamespaces()
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), namespaces)

	// Call GetNamespace on the first namespace in the list.
	namespace, err := suite.manager.GetNamespace(namespaces[0].Name)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), namespaces[0].Name, namespace.Name)
}

func (suite *ManagerTestSuite) TestFindPod() {
	var pods corev1.PodList
	err := suite.manager.Manager.GetCache().List(context.Background(), &pods, client.InNamespace("kube-system"))
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), pods.Items)
	pod, err := suite.manager.FindPod(string(pods.Items[0].UID))
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), pods.Items[0].UID, pod.UID)
}

func (suite *ManagerTestSuite) TestFindContainer() {
	// Create a pod.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "kube-system",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "nginx", Image: "nginx"}},
		},
	}
	k8sClient := suite.manager.Manager.GetClient()
	_ = k8sClient.Create(context.Background(), pod)

	// Get the container ID of the pod.
	podFromClient := corev1.Pod{}
	containerID := ""
	assert.Eventually(suite.T(), func() bool {
		err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &podFromClient)
		if err != nil {
			return false
		}
		containerID, err = watcher.ContainerIDKey(podFromClient.Status.ContainerStatuses[0].ContainerID)
		if err != nil {
			return false
		}
		return true
	}, 10*time.Second, 1*time.Second)

	// FindContainer should return the pod and container.
	podFromCache, container, found := suite.manager.FindContainer(containerID)
	assert.True(suite.T(), found)
	assert.Equal(suite.T(), pod.Name, podFromCache.Name)
	assert.Equal(suite.T(), pod.Spec.Containers[0].Name, container.Name)

	// Delete the pod.
	err := k8sClient.Delete(context.Background(), pod)
	assert.NoError(suite.T(), err)
	assert.Eventually(suite.T(), func() bool {
		err = k8sClient.Get(context.Background(), client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &podFromClient)
		return errors.IsNotFound(err)
	}, 10*time.Second, 1*time.Second)

	// FindContainer should still return the pod and container from the deleted pod cache.
	podFromCache, container, found = suite.manager.FindContainer(containerID)
	assert.True(suite.T(), found)
	assert.Equal(suite.T(), pod.Name, podFromCache.Name)
	assert.Equal(suite.T(), pod.Spec.Containers[0].Name, container.Name)
}

func (suite *ManagerTestSuite) TestLocalPods() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := os.Setenv("NODE_NAME", "nonexistent-node")
	assert.NoError(suite.T(), err)
	node.SetKubernetesNodeName()
	controllerManager, err := newControllerManager(false)
	assert.NoError(suite.T(), err)
	go func() {
		assert.NoError(suite.T(), controllerManager.Manager.Start(ctx))
	}()
	controllerManager.Manager.GetCache().WaitForCacheSync(ctx)
	pods := corev1.PodList{}
	err = controllerManager.Manager.GetCache().List(context.Background(), &pods)
	assert.NoError(suite.T(), err)
	// Pod cache should be empty because the node name is set to a nonexistent node.
	assert.Empty(suite.T(), pods.Items)
}

func (suite *ManagerTestSuite) TearDownSuite() {
	assert.NoError(suite.T(), suite.testEnv.Stop())
}

func TestControllerSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}
