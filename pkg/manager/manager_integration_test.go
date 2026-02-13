// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build integration

package manager

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/watcher"
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
	require.NoError(suite.T(), err)
	node.SetNodeName()
	useExistingCluster := true
	suite.testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
	}
	_, err = suite.testEnv.Start()
	require.NoError(suite.T(), err)
	suite.manager = Get()
	suite.manager.Start(context.Background())
}

func (suite *ManagerTestSuite) TestListNamespaces() {
	// List namespaces.
	namespaces, err := suite.manager.ListNamespaces()
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), namespaces)

	// Call GetNamespace on the first namespace in the list.
	namespace, err := suite.manager.GetNamespace(namespaces[0].Name)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), namespaces[0].Name, namespace.Name)
}

func (suite *ManagerTestSuite) TestFindPod() {
	var pods corev1.PodList
	err := suite.manager.Manager.GetCache().List(context.Background(), &pods, client.InNamespace("kube-system"))
	require.NoError(suite.T(), err)
	require.NotEmpty(suite.T(), pods.Items)
	pod, err := suite.manager.FindPod(string(pods.Items[0].UID))
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), pods.Items[0].UID, pod.UID)
}

func (suite *ManagerTestSuite) TestFindContainer() {
	// Create a pod with a unique name to avoid collisions.
	name := fmt.Sprintf("nginx-%d", time.Now().UnixNano())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kube-system",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: name, Image: "nginx"}},
		},
	}
	k8sClient := suite.manager.Manager.GetClient()
	err := k8sClient.Create(context.Background(), pod)
	require.NoError(suite.T(), err)

	// Get the container ID of the pod.
	podFromClient := corev1.Pod{}
	containerID := ""
	require.Eventually(suite.T(), func() bool {
		err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &podFromClient)
		if err != nil {
			return false
		}
		if len(podFromClient.Status.ContainerStatuses) == 0 {
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
	require.True(suite.T(), found)
	require.Equal(suite.T(), pod.Name, podFromCache.Name)
	assert.Equal(suite.T(), pod.Spec.Containers[0].Name, container.Name)

	// Delete the pod.
	err := k8sClient.Delete(context.Background(), pod)
	require.NoError(suite.T(), err)
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
	require.NoError(suite.T(), err)
	node.SetNodeName()
	controllerManager, err := newControllerManager()
	require.NoError(suite.T(), err)
	go func() {
		require.NoError(suite.T(), controllerManager.Manager.Start(ctx))
	}()
	controllerManager.Manager.GetCache().WaitForCacheSync(ctx)
	pods := corev1.PodList{}
	err = controllerManager.Manager.GetCache().List(context.Background(), &pods)
	require.NoError(suite.T(), err)
	// Pod cache should be empty because the node name is set to a nonexistent node.
	assert.Empty(suite.T(), pods.Items)
	require.NoError(suite.T(), os.Setenv("NODE_NAME", nodeName))
	node.SetNodeName()
}

func (suite *ManagerTestSuite) TestGetNode() {
	k8sNode, err := suite.manager.GetNode()
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), nodeName, k8sNode.Name)

	// Make sure it's only caching the local node.
	nodeList := corev1.NodeList{}
	err = suite.manager.Manager.GetCache().List(context.Background(), &nodeList)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), nodeList.Items, 1)
}

func (suite *ManagerTestSuite) TearDownSuite() {
	require.NoError(suite.T(), suite.testEnv.Stop())
}

func TestControllerSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}
