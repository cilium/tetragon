// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"context"
	"path/filepath"
	"time"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
)

// policy filter run-time hook

func init() {
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: createContainerHook,
	})
}

const (
	uidStringLen = len("00000000-0000-0000-0000-000000000000")
)

func createContainerHook(_ context.Context, arg *rthooks.CreateContainerArg) error {
	var err error

	log := logger.GetLogger().WithFields(logrus.Fields{
		"sub-system": "rthook.policyfilter",
		"hook":       "create-container",
	})

	pfState, err := policyfilter.GetState()
	if err != nil {
		log.WithError(err).Warn("failed to retreieve policyfilter state, aborting hook")
	}

	// retrieve the cgroup id from the host cgroup path.
	//
	// NB(kkourt): A better solution might be to hook into cgroup creation routines and create a
	// mapping between directory and cgroup id that we maintain in user-space. Then, we can find
	// the id using this mapping.
	cgPath := arg.Req.CgroupsPath
	cgRoot, err := cgroups.HostCgroupRoot()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve host cgroup root, aborting hook")
		return err
	}
	path := filepath.Join(cgRoot, cgPath)
	cgID, err := cgroups.GetCgroupIdFromPath(path)
	if err != nil {
		log.WithError(err).WithField("path", path).WithField("cgroup-id", cgID).Warn("retrieving cgroup id failed, aborting hook")
		return err
	}

	containerID := filepath.Base(cgPath)
	podPath := filepath.Dir(cgPath)
	podIDstr := filepath.Base(podPath)
	if len(podIDstr) > uidStringLen {
		// remove pod prefix
		podIDstr = podIDstr[len(podIDstr)-uidStringLen:]
	}
	podID, err := uuid.Parse(podIDstr)
	if err != nil {
		log.WithError(err).WithField("uuid", podIDstr).WithField("cgroup-path", cgPath).Warn("failed to parse uuid, aborting hook")
		return err
	}

	// Because we are still creating the container, its status is not available at the k8s API.
	// Instead, we use the PodID.
	var pod *corev1.Pod
	nretries := 5
	for i := 0; i < nretries; i++ {
		pod, err = arg.Watcher.FindPod(podIDstr)
		if err == nil {
			break
		}
		log.Infof("failed to get pod info from watcher (%T): will retry (%d/%d).", arg.Watcher, i+1, nretries)
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		log.WithError(err).Warn("failed to get pod info, aborting hook.")
		return err
	}

	namespace := pod.ObjectMeta.Namespace

	containerName := arg.Req.ContainerName
	if containerName == "" {
		log.Warnf("failed to find container information for %s, but will continue", containerID)
		policyfiltermetrics.ContNameMissInc()
	}

	log.WithFields(logrus.Fields{
		"pod-id":         podID,
		"namespace":      namespace,
		"container-id":   containerID,
		"cgroup-id":      cgID,
		"container-name": containerName,
	}).Trace("policyfilter: add pod container")
	cgid := policyfilter.CgroupID(cgID)
	err = pfState.AddPodContainer(policyfilter.PodID(podID), namespace, pod.Labels, containerID, cgid, containerName)
	policyfiltermetrics.OpInc(policyfiltermetrics.RTHooksSubsys, policyfiltermetrics.AddContainerOperation, policyfilter.ErrorLabel(err))

	if err != nil {
		log.WithError(err).Warn("failed to update policy filter, aborting hook.")
		return err
	}

	return nil
}
