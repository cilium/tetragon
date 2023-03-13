// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

// Policy filter is a mechanism for restricting  tracing policies on a subset
// of pods running in the node. Policies are identified by their policyID and
// the pod processes are identified the cgroup ids of their containers.
//
// The pods that match a given policy are selected based on:
//   (1) Namespaces
//   (2) Label filters (NYI, see Todo)
//
// This package maintains the 'policy_filter_maps' bpf map. Bpf checks this map
// to decide whether a policy is applied or not. The map is a hash-of-hashes:
//
//   policy_id -> [ cgroup_id -> u8 ]
//
// If entry policy_id -> cgroup_id exists, then policy is to be applied. (u8 value is ignored for
// now.)
//
// This package provides functions that can be used to update the bpf map. The map
// needs to be updated in the following conditions:
//
//  (A) Policy changes: when a new policy is added (or deleted), we need to add cgroup ids of
//  matching pods. See {Add,Del}Policy.
//
//  (B) Pod containers changes: when new containers are added (or deleted): we need to add the cgroup
//  ids of matching policies. See AddPodContainer, DelPodContainer, DelPod.
//
//  (C) Pod labels change: need to rescan policies because the result of pod label filters might have
//  changed.  (NYI, see Todo)
//
// Todo:
//  - deal with (C) to handle (2). Plan is:
//       - add a label matcher to policies
//       - use k8s watcher to retrieve labels for all pods (by their pod id).
//  - use a gouritine and a channel instead locks for serilization
//  - periodic (or via external command) rescans to ensure that everything is up-to-date
//  - optimization: policy<->pod matching caching so that we can go from pod -> matching policies
//  without having to check all policies. Note that this would have to account for new
//  policies added. Since we are only matching on namespace, we iterate over all policies for now
//  since the performance impact of above optimization would be small.

func init() {
	podhooks.RegisterCallbacksAtInit(podhooks.Callbacks{
		PodCallbacks: func(podInformer cache.SharedIndexInformer) {
			// register pod handlers for policyfilters
			if pfState, err := GetState(); err == nil {
				logger.GetLogger().Info("registering policyfilter pod handlers")
				pfState.RegisterPodHandlers(podInformer)
			}
		},
	})
}

const (
	// polMapSize is the number of entries for the (inner) policy map. It
	// should be large enough to accommodate the number of containers
	// running in a system.
	polMapSize = 32768
)

type PolicyID uint32
type PodID uuid.UUID
type CgroupID uint64

func (i PodID) String() string {
	var x uuid.UUID = uuid.UUID(i)
	return x.String()
}

type containerInfo struct {
	id   string   // container id
	cgID CgroupID // cgroup id
}

// podInfo contains the necessary information for each pod
type podInfo struct {
	id         PodID
	namespace  string
	containers []containerInfo
}

func (pod *podInfo) cgroupIDs() []CgroupID {
	ret := make([]CgroupID, 0, len(pod.containers))
	for i := range pod.containers {
		ret = append(ret, pod.containers[i].cgID)
	}
	return ret
}

// delete containers from a pod based on their id, and return them
// NB: in most cases there will be a single container, but we do not reject users adding a container
// with the same id and different cgroup, so we return a list to cover all cases.
func (pod *podInfo) delContainers(id string) []containerInfo {
	var ret []containerInfo
	for i := 0; i < len(pod.containers); i++ {
		c := pod.containers[i]
		if c.id == id {
			ret = append(ret, c)
			pod.containers = append(pod.containers[:i], pod.containers[i+1:]...)
			i--
		}
	}
	return ret
}

// containerExists checks returns true if a container exists in the pod
// it uses log to log inconsistencies in the data.
func (pod *podInfo) containerExists(log logrus.FieldLogger, containerID string, cgIDp *CgroupID) bool {
	for i := range pod.containers {
		container := &pod.containers[i]
		if container.id != containerID {
			continue
		}

		// we found a matching container id, if no cgroup id is given, return
		if cgIDp == nil {
			return true
		}

		// otherwise, also check that the cgroup id matches
		if container.id == containerID && container.cgID == *cgIDp {
			// container was already handled, return
			return true
		}

		// issue  a warning and continue
		// NB: if this happens, we might end up with multiple cgroup
		// ids for the same container. Since we have no way of knowing
		// which one is the correct, we keep both.
		log.WithFields(logrus.Fields{
			"container-id":  containerID,
			"old-cgroup-id": container.cgID,
			"new-cgroup-id": *cgIDp,
		}).Warnf("AddPodContainer: conflicting cgroup ids")
	}

	return false
}

type policy struct {
	id PolicyID

	// if namespace is "", policy applies to all namespaces
	namespace string

	// polMap is the (inner) policy map for this policy
	polMap polMap
}

func (pol *policy) podMatches(pod *podInfo) bool {
	if pol.namespace == "" {
		return true
	}
	return pol.namespace == pod.namespace
}

// State holds the necessary state for policyfilter
type state struct {
	log logrus.FieldLogger

	// mutex serializes access to the internal structures, as well as operations.
	mu       sync.Mutex
	policies []policy
	pods     []podInfo

	// polify filters (outer) map handle
	pfMap PfMap

	// cgroup fs scanner
	cgfsScanner fsscan.FsScanner
}

// New creates a new State of the policy filter code. Callers should call Close() to release
// allocated resources (namely the bpf map).
//
//revive:disable:unexported-return
func New() (*state, error) {
	var err error
	ret := &state{
		log:         logger.GetLogger().WithField("subsystem", "policy-filter"),
		cgfsScanner: fsscan.New(),
	}

	ret.pfMap, err = newPfMap()
	if err != nil {
		return nil, err
	}

	return ret, nil
}

//revive:enable:unexported-return

func (m *state) RegisterPodHandlers(podInformer cache.SharedIndexInformer) {
	podInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, ok := obj.(*v1.Pod)
				if !ok {
					logger.GetLogger().Warn("policyfilter, add-pod handler: unexpected object type: %T", pod)
					return
				}
				containerIDs := podContainersIDs(pod)
				podID, err := uuid.Parse(string(pod.UID))
				if err != nil {
					logger.GetLogger().WithField("pod-id", pod.UID).WithError(err).Warn("policyfilter, add-pod handler: failed to parse pod id")
					return

				}

				namespace := pod.Namespace
				for _, contID := range containerIDs {
					err := m.AddPodContainer(PodID(podID), namespace, contID, nil)
					if err != nil {
						logger.GetLogger().WithError(err).WithFields(logrus.Fields{
							"pod-id":       podID,
							"container-id": contID,
							"namespace":    namespace,
						}).Warn("policyfilter, add pod-handler: AddPodContainer failed")
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				pod1, ok1 := oldObj.(*v1.Pod)
				pod2, ok2 := newObj.(*v1.Pod)
				if !ok1 || !ok2 {
					logger.GetLogger().Warn("policyfilter, update-pod: unexpected object type(s): old:%T new:%T", pod1, pod2)
					return
				}
				if pod1.UID != pod2.UID {
					logger.GetLogger().Warn("policyfilter, update-pod: unexpected pod ids: old:%T new:%T", pod1.UID, pod2.UID)
					return
				}

				podID, err := uuid.Parse(string(pod1.UID))
				if err != nil {
					logger.GetLogger().WithField("pod-id", pod1.UID).WithError(err).Warn("policyfilter, update-pod: failed to parse id")
					return
				}

				namespace := pod1.Namespace
				addedIDs, deletedIDs := podContainerDiff(pod1, pod2)
				for _, contID := range deletedIDs {
					m.DelPodContainer(PodID(podID), contID)
					if err != nil {
						logger.GetLogger().WithError(err).WithFields(logrus.Fields{
							"pod-id":       podID,
							"container-id": contID,
							"namespace":    namespace,
						}).Warn("policyfilter, update-pod handler: DelPodContainer failed")
					}
				}
				for _, contID := range addedIDs {
					err := m.AddPodContainer(PodID(podID), namespace, contID, nil)
					if err != nil {
						logger.GetLogger().WithError(err).WithFields(logrus.Fields{
							"pod-id":       podID,
							"container-id": contID,
							"namespace":    namespace,
						}).Warn("policyfilter, update-pod handler: AddPodContainer failed")
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				// Remove all containers for this pod
				pod, ok := obj.(*v1.Pod)
				if !ok {
					logger.GetLogger().Warn("policyfilter, delete-pod handler: unexpected object type: %T", pod)
					return
				}
				podID, err := uuid.Parse(string(pod.UID))
				if err != nil {
					logger.GetLogger().WithField("pod-id", pod.UID).WithError(err).Warn("policyfilter, delete-pod: failed to parse id")
					return
				}

				namespace := pod.Namespace
				err = m.DelPod(PodID(podID))
				if err != nil {
					logger.GetLogger().WithError(err).WithFields(logrus.Fields{
						"pod-id":    podID,
						"namespace": namespace,
					}).Warn("policyfilter, delete-pod handler: DelPod failed")
				}
			},
		})
}

// Close releases resources allocated by the Manager. Specifically, we close and unpin the policy filter map.
func (m *state) Close() error {
	return m.pfMap.release()
}

func (m *state) findPolicy(id PolicyID) *policy {
	for i := range m.policies {
		if m.policies[i].id == id {
			return &m.policies[i]
		}
	}
	return nil
}

// delPolicy removes a policy and returns it, or returns nil if policy is not found
func (m *state) delPolicy(id PolicyID) *policy {
	for i, pol := range m.policies {
		if pol.id == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return &pol
		}
	}
	return nil
}

func (m *state) findPod(id PodID) *podInfo {
	for i := range m.pods {
		if m.pods[i].id == id {
			return &m.pods[i]
		}
	}
	return nil
}

func (m *state) delPod(id PodID) *podInfo {
	for i, pod := range m.pods {
		if pod.id == id {
			m.pods = append(m.pods[:i], m.pods[i+1:]...)
			return &pod
		}
	}
	return nil
}

// AddPolicy adds a policy
func (m *state) AddPolicy(polID PolicyID, namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p := m.findPolicy(polID); p != nil {
		return fmt.Errorf("policy with id %d already exists: not adding new one", polID)
	}
	policy := policy{
		id:        polID,
		namespace: namespace,
	}

	cgroupIDs := make([]CgroupID, 0)
	// scan pods to find the ones that match this policy to set initial state for policy
	for podIdx := range m.pods {
		pod := &m.pods[podIdx]
		if !policy.podMatches(pod) {
			continue
		}
		for cIdx := range pod.containers {
			cgroupIDs = append(cgroupIDs, pod.containers[cIdx].cgID)
		}
	}

	// update state for policy
	var err error
	policy.polMap, err = m.pfMap.newPolicyMap(polID, cgroupIDs)
	if err != nil {
		return fmt.Errorf("adding policy data to map failed: %w", err)
	}
	m.policies = append(m.policies, policy)
	return nil
}

// DelPolicy will destroly all information for the provided policy
func (m *state) DelPolicy(polID PolicyID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	policy := m.delPolicy(polID)
	if policy != nil {
		policy.polMap.Close()
	} else {
		m.log.WithField("policy-id", polID).Warn("DelPolicy: policy internal map not found")
	}

	if err := m.pfMap.Delete(polID); err != nil {
		m.log.WithField("policy-id", polID).Warn("DelPolicy: failed to remove policy from external map")
	}

	return nil
}

func (m *state) addPod(podID PodID, namespace string, containers []containerInfo) error {
	m.pods = append(m.pods, podInfo{
		id:         podID,
		namespace:  namespace,
		containers: containers,
	})
	pod := &m.pods[len(m.pods)-1]
	cgroupIDs := pod.cgroupIDs()
	for polID := range m.policies {
		pol := &m.policies[polID]
		if !pol.podMatches(pod) {
			continue
		}

		if err := pol.polMap.addCgroupIDs(cgroupIDs); err != nil {
			// NB: depending on the error, we might want to schedule some retries here
			m.log.WithError(err).WithFields(logrus.Fields{
				"policy-id":  polID,
				"pod-id":     podID,
				"cgroup-ids": cgroupIDs,
			}).Warn("addPod: failed to update policy map")
		}
	}

	return nil
}

func cgIDPtrStr(p *CgroupID) string {
	if p == nil {
		return "(unknown)"
	}
	return fmt.Sprintf("%d", *p)
}

func (m *state) findCgroupID(podID PodID, containerID string) (CgroupID, error) {
	path, err := m.cgfsScanner.FindContainerPath(uuid.UUID(podID), containerID)
	if errors.Is(err, fsscan.ErrContainerPathWithoutMatchingPodID) {
		m.log.WithFields(logrus.Fields{
			"pod-id":       podID,
			"container-id": containerID,
		}).Info("findCgroupID: found path without matching pod id, continuing.")
	} else if err != nil {
		return CgroupID(0), err
	}
	cgid, err := cgroups.GetCgroupIdFromPath(path)
	return CgroupID(cgid), err
}

// AddPodContainer informs policyfilter about a new container in a pod.
// if the cgroup id of the container is known, cgID is not nil and it contains its value.
//
// The pod might or might not have been encountered before.
func (m *state) AddPodContainer(podID PodID, namespace string, containerID string, cgIDp *CgroupID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log := m.debugLogWithCallers(4).WithFields(logrus.Fields{
		"pod-id":       podID,
		"namespace":    namespace,
		"container-id": containerID,
		"cgroup-id":    cgIDPtrStr(cgIDp),
	})

	pod := m.findPod(podID)
	if pod == nil {
		// try to detrmine cgroup id, if not provided
		var cgID CgroupID
		var err error
		if cgIDp != nil {
			cgID = *cgIDp
		} else if cgID, err = m.findCgroupID(podID, containerID); err != nil {
			return fmt.Errorf("failed to determine cgroup id for new PodID=%s ContainerID=%s, err:%v", podID, containerID, err)
		}
		log.Info("AddPodContainer: adding new pod")
		return m.addPod(podID, namespace, []containerInfo{{id: containerID, cgID: cgID}})
	}

	// sanity check: old and new namespace should match
	if pod.namespace != namespace {
		return fmt.Errorf("conflicting namespaces for pod with id %s: old='%s' vs new='%s'", podID, pod.namespace, namespace)
	}

	if pod.containerExists(m.log.WithField("pod-id", podID), containerID, cgIDp) {
		m.Debugf("AddPodContainer: container exists")
		// container was already handled, return
		return nil
	}

	// try to detrmine cgroup id, if not provided
	var cgID CgroupID
	var err error
	if cgIDp != nil {
		cgID = *cgIDp
	} else if cgID, err = m.findCgroupID(podID, containerID); err != nil {
		return fmt.Errorf("failed to determine cgroup id for PodID=%s ContainerID=%s, err:%v", podID, containerID, err)
	}
	// add container to pod containers
	pod.containers = append(pod.containers, containerInfo{
		id:   containerID,
		cgID: cgID,
	})

	cgroupIDs := []CgroupID{cgID}
	// check what policies match the pod, and add the new cgroup id if they match
	// NB(kkourt): matching info can be cached, but not sure if it is worth it
	for polID := range m.policies {
		pol := &m.policies[polID]
		if !pol.podMatches(pod) {
			continue
		}

		if err := pol.polMap.addCgroupIDs(cgroupIDs); err != nil {
			// NB: depending on the error, we might want to schedule some retries here
			m.log.WithError(err).WithFields(logrus.Fields{
				"policy-id":  polID,
				"pod-id":     podID,
				"cgroup-ids": cgroupIDs,
			}).Warn("AddPodContainer: failed to update policy map")
		}
	}

	log.Info("AddPodContainer: added container to existing pod")
	return nil
}

// delPodCgroupIDsFromPolicyMaps will delete cgorup entries for containers belonging to pod on all
// policy maps.
func (m *state) delPodCgroupIDsFromPolicyMaps(pod *podInfo, containers []containerInfo) {

	if len(containers) == 0 {
		return
	}

	cgroupIDs := make([]CgroupID, 0, len(containers))
	for i := range containers {
		cgroupIDs = append(cgroupIDs, containers[i].cgID)
	}

	// check what policies match the pod, and delete the cgroup ids
	// NB(kkourt): matching info can be cached, but not sure if it is worth it
	for i := range m.policies {
		pol := &m.policies[i]
		if !pol.podMatches(pod) {
			continue
		}

		if err := pol.polMap.delCgroupIDs(cgroupIDs); err != nil {
			// NB: depending on the error, we might want to schedule some retries here
			m.log.WithError(err).WithFields(logrus.Fields{
				"policy-id":  pol.id,
				"pod-id":     pod.id,
				"cgroup-ids": cgroupIDs,
			}).Warn("AddPodContainer: failed to delete cgroup ids from policy map")
		}
	}
}

// DelPodContainer informs policyfilter that a container was deleted from a pod
func (m *state) DelPodContainer(podID PodID, containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pod := m.findPod(podID)
	if pod == nil {
		m.Debugf("DelPodContainer: pod-id %s not found", podID)
		return nil
	}

	containers := pod.delContainers(containerID)
	if len(containers) != 1 {
		m.Debugf("DelPodContainer: pod-id=%s container-id=%s had %d containers: %v", podID, containerID, len(containers), containers)
	}
	m.delPodCgroupIDsFromPolicyMaps(pod, containers)
	return nil
}

// DelPod informs policyfilter that a pod has been deleted
func (m *state) DelPod(podID PodID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pod := m.delPod(podID)
	if pod == nil {
		m.Debug("DelPod: pod-id %s not found", podID)
		return nil
	}
	m.delPodCgroupIDsFromPolicyMaps(pod, pod.containers)
	return nil
}
