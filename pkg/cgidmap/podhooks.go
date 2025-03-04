// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgidmap

import (
	"errors"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/podhooks"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

func init() {
	podhooks.RegisterCallbacksAtInit(podhooks.Callbacks{
		PodCallbacks: func(podInformer cache.SharedIndexInformer) {
			registerPodCallbacks(podInformer)
		},
	})
}

func registerPodCallbacks(podInformer cache.SharedIndexInformer) {

	m, err := GlobalMap()
	if err != nil {
		// if cgidmap is disabled, an error is expected so do not omit a warning
		if !errors.Is(err, cgidDisabled) {
			logger.GetLogger().WithError(err).Warn("failed to retrieve cgidmap, not registering podhook")
		}
		return
	}

	podInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, ok := obj.(*v1.Pod)
				if !ok {
					logger.GetLogger().Warn("cgidmap, add-pod handler: unexpected object type: %T", pod)
					return
				}
				updatePodHandler(m, pod)
			},
			UpdateFunc: func(_, newObj interface{}) {
				pod, ok := newObj.(*v1.Pod)
				if !ok {
					logger.GetLogger().Warn("cgidmap, update-pod handler: unexpected object type(s): new:%T", pod)
					return
				}
				updatePodHandler(m, pod)
			},
			DeleteFunc: func(obj interface{}) {
				var pod *corev1.Pod
				switch concreteObj := obj.(type) {
				case *corev1.Pod:
					pod = concreteObj
				case cache.DeletedFinalStateUnknown:
					// Handle the case when the watcher missed the deletion event
					// (e.g. due to a lost apiserver connection).
					deletedObj, ok := concreteObj.Obj.(*corev1.Pod)
					if !ok {
						return
					}
					pod = deletedObj
				default:
					return
				}
				deletePodHandler(m, pod)

			},
		},
	)
}

func deletePodHandler(m Map, pod *corev1.Pod) {
	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("pod-id", pod.UID).Warn("cgidmap, podDeleted: failed to parse pod id")
		return
	}
	m.Update(podID, nil)
}

func updatePodHandler(m Map, pod *corev1.Pod) {
	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("pod-id", pod.UID).Warn("cgidmap, podDeleted: failed to parse pod id")
		return
	}
	m.Update(podID, podhelpers.PodContainersIDs(pod))
}
