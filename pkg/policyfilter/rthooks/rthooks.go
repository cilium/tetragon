// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/rthooks"
)

// policy filter run-time hook

func init() {
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: createContainerHook,
	})
}

func createContainerHook(_ context.Context, arg *rthooks.CreateContainerArg) error {
	var err error

	log := logger.GetLogger().With(
		"sub-system", "rthook.policyfilter",
		"hook", "create-container",
	)

	pfState, err := policyfilter.GetState()
	if err != nil {
		log.Warn("failed to retrieve policyfilter state, aborting hook", logfields.Error, err)
		return err
	}

	cgID, err := arg.CgroupID()
	if err != nil {
		log.Warn("failed to retrieve cgroup id, aborting hook", logfields.Error, err)
		return err
	}

	podIDstr, err := arg.PodID()
	if err != nil {
		log.Warn("failed to retrieve pod id, aborting hook", logfields.Error, err)
		return err
	}

	cgPath := arg.Req.CgroupsPath
	podID, err := uuid.Parse(podIDstr)
	if err != nil {
		log.Warn("failed to parse uuid, aborting hook", logfields.Error, err, "uuid", podIDstr, "cgroup-path", cgPath)
		return err
	}

	containerID, err := arg.ContainerID()
	if err != nil {
		log.Warn("failed to retrieve container id, aborting hook", logfields.Error, err)
		return err
	}

	// Because we are still creating the container, its status is not available at the k8s API.
	// Instead, we retrieve the pod
	pod, err := arg.Pod()
	if err != nil {
		log.Warn("failed to get pod info, aborting hook.", logfields.Error, err)
		return err
	}

	namespace := pod.Namespace
	workloadMeta, workloadKind := podhelpers.GetWorkloadMetaFromPod(pod)
	workload := workloadMeta.Name
	kind := workloadKind.Kind

	containerName := arg.Req.ContainerName
	if containerName == "" {
		log.Warn("failed to find container information, but will continue", "container-id", containerID)
		policyfiltermetrics.ContNameMissInc()
	}

	containerImage := arg.Req.ContainerImage
	if containerImage == "" {
		log.Warn("failed to find container image, but will continue", "container-id", containerID)
		policyfiltermetrics.ContImageMissInc()
	}

	containerRepo := containerImage
	containerImageParts := strings.Split(containerImage, ":")
	if len(containerImageParts) == 2 {
		containerRepo = containerImageParts[0]
	}

	logger.Trace(log, "policyfilter: add pod container",
		"pod-id", podID,
		"namespace", namespace,
		"workload", workload,
		"workload-kind", kind,
		"container-id", containerID,
		"cgroup-id", cgID,
		"container-name", containerName)
	cgid := policyfilter.CgroupID(cgID)
	err = pfState.AddPodContainer(policyfilter.PodID(podID), namespace, workload, kind, pod.Labels, containerID, cgid, podhelpers.ContainerInfo{Name: containerName, Repo: containerRepo})
	policyfiltermetrics.OpInc(policyfiltermetrics.RTHooksSubsys, policyfiltermetrics.AddContainerOperation, policyfilter.ErrorLabel(err))

	if err != nil {
		log.Warn("failed to update policy filter, aborting hook.", "logfields.Error", err)
		return err
	}

	return nil
}
