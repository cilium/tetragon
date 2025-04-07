// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetNamespace(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	k8sWatcher := NewK8sWatcher(k8sClient, nil, 60*time.Second)
	err := AddNamespaceInformer(k8sWatcher)
	assert.NoError(t, err)
	k8sWatcher.Start()
	ns1 := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "ns1"},
	}
	ns2 := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "ns2"},
	}
	_, err = k8sClient.CoreV1().Namespaces().Create(ctx, &ns1, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = k8sClient.CoreV1().Namespaces().Create(ctx, &ns2, metav1.CreateOptions{})
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		return len(k8sWatcher.GetInformer(namespaceInformerName).GetStore().List()) == 2
	}, 10*time.Second, 1*time.Second)
	res, err := k8sWatcher.GetNamespace("ns1")
	assert.NoError(t, err)
	assert.Equal(t, "ns1", res.Name)
	res, err = k8sWatcher.GetNamespace("ns2")
	assert.NoError(t, err)
	assert.Equal(t, "ns2", res.Name)
	_, err = k8sWatcher.GetNamespace("ns3")
	assert.Error(t, err)
}
