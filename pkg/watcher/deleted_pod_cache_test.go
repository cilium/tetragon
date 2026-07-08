// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package watcher

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"github.com/cilium/tetragon/pkg/option"
)

type DeletedPodCacheTestSuite struct {
	suite.Suite
	originalDeletedPodCacheSize int
	cache                       *DeletedPodCache
}

func (suite *DeletedPodCacheTestSuite) SetupSuite() {
	suite.originalDeletedPodCacheSize = option.Config.DeletedPodCacheSize
	option.Config.DeletedPodCacheSize = 1

	cache, err := NewDeletedPodCache()
	suite.Require().NoError(err)
	suite.cache = cache
}

func (suite *DeletedPodCacheTestSuite) TestMetrics() {
	firstContainerID := "container-id-1"
	secondContainerID := "container-id-2"

	firstPod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: firstContainerID},
			},
		},
	}

	secondPod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: secondContainerID},
			},
		},
	}

	hitsBefore := testutil.ToFloat64(watchermetrics.GetWatcherDeletedPodCacheHits())
	evictionsBefore := testutil.ToFloat64(watchermetrics.GetWatcherDeletedPodCacheEvictions())

	suite.cache.Add(firstContainerID, deletedPodCacheEntry{
		pod:        firstPod,
		contStatus: &firstPod.Status.ContainerStatuses[0],
	})

	pod, _, found := suite.cache.FindContainer(firstContainerID)
	suite.Require().True(found)
	suite.Require().NotNil(pod)

	hitsAfterFirstFind := testutil.ToFloat64(watchermetrics.GetWatcherDeletedPodCacheHits())
	suite.InDelta(hitsBefore+1, hitsAfterFirstFind, 1e-9)

	// This will evict the first entry added and increment the evicted count.
	suite.cache.Add(secondContainerID, deletedPodCacheEntry{
		pod:        secondPod,
		contStatus: &secondPod.Status.ContainerStatuses[0],
	})

	_, _, found = suite.cache.FindContainer(firstContainerID)
	suite.False(found)

	evictionsAfter := testutil.ToFloat64(watchermetrics.GetWatcherDeletedPodCacheEvictions())
	suite.InDelta(evictionsBefore+1, evictionsAfter, 1e-9)
}

func (suite *DeletedPodCacheTestSuite) TearDownSuite() {
	option.Config.DeletedPodCacheSize = suite.originalDeletedPodCacheSize
}

func TestDeletedPodCacheSuite(t *testing.T) {
	suite.Run(t, new(DeletedPodCacheTestSuite))
}
