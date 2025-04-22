// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"context"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// policy filter run-time hook

func init() {
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: createContainerHook,
	})
}

func createContainerHook(_ context.Context, arg *rthooks.CreateContainerArg) error {
	var err error

	log := logger.GetLogger().WithFields(logrus.Fields{
		"sub-system": "rthook.policyfilter",
		"hook":       "create-container",
	})

	pfState, err := policyfilter.GetState()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve policyfilter state, aborting hook")
		return err
	}

	cgID, err := arg.CgroupID()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve cgroup id, aborting hook")
		return err
	}

	podIDstr, err := arg.PodID()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve pod id, aborting hook")
		return err
	}

	cgPath := arg.Req.CgroupsPath
	podID, err := uuid.Parse(podIDstr)
	if err != nil {
		log.WithError(err).WithField("uuid", podIDstr).WithField("cgroup-path", cgPath).Warn("failed to parse uuid, aborting hook")
		return err
	}

	containerID, err := arg.ContainerID()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve container id, aborting hook")
		return err
	}

	// Because we are still creating the container, its status is not available at the k8s API.
	// Instead, we retrieve the pod
	pod, err := arg.Pod()
	if err != nil {
		log.WithError(err).Warn("failed to get pod info, aborting hook.")
		return err
	}

	namespace := pod.Namespace
	topLevelWorkload := podhelpers.GetTopLevelWorkloadFromPod(pod)
	workload := topLevelWorkload.Name
	kind := topLevelWorkload.Kind

	containerName := arg.Req.ContainerName
	if containerName == "" {
		log.Warnf("failed to find container information for %s, but will continue", containerID)
		policyfiltermetrics.ContNameMissInc()
	}

	log.WithFields(logrus.Fields{
		"pod-id":         podID,
		"namespace":      namespace,
		"workload":       workload,
		"workload-kind":  kind,
		"container-id":   containerID,
		"cgroup-id":      cgID,
		"container-name": containerName,
	}).Trace("policyfilter: add pod container")
	cgid := policyfilter.CgroupID(cgID)
	err = pfState.AddPodContainer(policyfilter.PodID(podID), namespace, workload, kind, pod.Labels, containerID, cgid, containerName)
	policyfiltermetrics.OpInc(policyfiltermetrics.RTHooksSubsys, policyfiltermetrics.AddContainerOperation, policyfilter.ErrorLabel(err))

	if err != nil {
		log.WithError(err).Warn("failed to update policy filter, aborting hook.")
		return err
	}

	return nil
}
