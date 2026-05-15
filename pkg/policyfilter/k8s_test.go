// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s && !windows

package policyfilter

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

// Testing of policyfilter using a hand-rolled fake PodEventSource.
//
// The idea is to drive the policyfilter's pod handlers directly from the test
// (no informer, no fake clientset) and assert the resulting state of the
// policy filter bpf map. Because callbacks are invoked synchronously, the
// previous waitForCallbacks dance is no longer needed.

type tlog struct {
	*testing.T
	Logger *slog.Logger
}

func (tl tlog) Write(p []byte) (n int, err error) {
	tl.Log(string(p))
	return len(p), nil
}

type testContainer struct {
	name string
	id   string
	cgID CgroupID
}

type testPod struct {
	name       string
	id         uuid.UUID
	namespace  string
	labels     labels.Labels
	containers []testContainer
}

func (ts *testState) randString(length int) string {
	b := make([]byte, length+2)
	ts.rnd.Read(b)
	return hex.EncodeToString(b)[2 : length+2]
}

// testState provides helper functions for creating/updating pods and a fake
// cgroup-id finder.
type testState struct {
	pods   []testPod
	rnd    *rand.Rand
	source *fakePodEventSource
}

func newTestState(source *fakePodEventSource) *testState {
	return &testState{
		rnd:    rand.New(rand.NewSource(time.Now().UnixNano())),
		source: source,
	}
}

// fakePodEventSource is a hand-rolled fake satisfying policyfilter.PodEventSource.
// It captures the registered handlers so the test can fire events synchronously.
// Each event type holds a slice of handlers — matching the production adapter,
// which supports independent registrations from multiple consumers on the same
// informer.
type fakePodEventSource struct {
	addHandlers    []func(*v1.Pod)
	updateHandlers []func(*v1.Pod, *v1.Pod)
	deleteHandlers []func(*v1.Pod)
}

func (f *fakePodEventSource) OnPodAdd(handler func(pod *v1.Pod)) {
	f.addHandlers = append(f.addHandlers, handler)
}

func (f *fakePodEventSource) OnPodUpdate(handler func(oldPod, newPod *v1.Pod)) {
	f.updateHandlers = append(f.updateHandlers, handler)
}

func (f *fakePodEventSource) OnPodDelete(handler func(pod *v1.Pod)) {
	f.deleteHandlers = append(f.deleteHandlers, handler)
}

func (f *fakePodEventSource) firePodAdd(pod *v1.Pod) {
	for _, h := range f.addHandlers {
		h(pod)
	}
}

func (f *fakePodEventSource) firePodUpdate(oldPod, newPod *v1.Pod) {
	for _, h := range f.updateHandlers {
		h(oldPod, newPod)
	}
}

func (f *fakePodEventSource) firePodDelete(pod *v1.Pod) {
	for _, h := range f.deleteHandlers {
		h(pod)
	}
}

func (tp *testPod) Pod() *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tp.name,
			UID:       k8stypes.UID(tp.id.String()),
			Namespace: tp.namespace,
			Labels:    tp.labels,
		},
		Spec:   v1.PodSpec{},
		Status: v1.PodStatus{},
	}

	for _, cont := range tp.containers {
		pod.Spec.Containers = append(pod.Spec.Containers, v1.Container{
			Name: cont.name,
		})
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, v1.ContainerStatus{
			Name:        cont.name,
			ContainerID: cont.id,
			State: v1.ContainerState{
				Running: &v1.ContainerStateRunning{},
			},
		})
	}

	return pod
}

func (ts *testState) newTestContainer(name string) testContainer {
	contID := fmt.Sprintf("%s-%s", name, ts.randString(8))
	cgID := CgroupID(ts.rnd.Uint64())
	return testContainer{
		name: name,
		id:   contID,
		cgID: cgID,
	}
}

func (ts *testState) createPod(_ *testing.T, name string, namespace string, podLabels labels.Labels, containerNames ...string) {
	podID := uuid.New()
	tp := testPod{
		name:      name,
		id:        podID,
		namespace: namespace,
		labels:    podLabels,
	}

	for _, contName := range containerNames {
		tp.containers = append(tp.containers, ts.newTestContainer(contName))
	}
	ts.pods = append(ts.pods, tp)

	ts.source.firePodAdd(tp.Pod())
}

func (ts *testState) findPod(t *testing.T, name string) *testPod {
	var tp *testPod
	for i := range ts.pods {
		if ts.pods[i].name == name {
			tp = &ts.pods[i]
		}
	}
	require.NotNil(t, tp)
	return tp
}

func (ts *testState) updatePodContainers(t *testing.T, name string, containerNames ...string) {
	tp := ts.findPod(t, name)
	oldPod := tp.Pod()
	containers := map[string]testContainer{}
	for _, cont := range tp.containers {
		containers[cont.name] = cont
	}

	newContainers := make([]testContainer, 0, len(containerNames))
	for _, contName := range containerNames {
		var newCont testContainer
		if oldCont, ok := containers[contName]; ok {
			newCont = oldCont
		} else {
			newCont = ts.newTestContainer(contName)
		}
		newContainers = append(newContainers, newCont)
	}
	tp.containers = newContainers

	ts.source.firePodUpdate(oldPod, tp.Pod())
}

func (ts *testState) updatePodLabels(t *testing.T, name string, podLabels labels.Labels) {
	tp := ts.findPod(t, name)
	oldPod := tp.Pod()
	tp.labels = podLabels
	ts.source.firePodUpdate(oldPod, tp.Pod())
}

func (ts *testState) deletePod(t *testing.T, name string) {
	var p *testPod
	for idx, pod := range ts.pods {
		if pod.name == name {
			tmp := pod
			p = &tmp
			ts.pods = append(ts.pods[:idx], ts.pods[idx+1:]...)
			break
		}
	}
	if p == nil {
		t.Fatalf("unknown pod name: %s", name)
	}
	ts.source.firePodDelete(p.Pod())
}

// testState implements cgFinder
func (ts *testState) findCgroupID(podID PodID, containerID string) (CgroupID, error) {
	var p *testPod
	for _, pod := range ts.pods {
		if PodID(pod.id) == podID {
			p = &pod
			break
		}
	}

	if p == nil {
		return CgroupID(0), fmt.Errorf("unknown pod id: %s", podID)
	}

	for _, cont := range p.containers {
		if cont.id == containerID {
			return cont.cgID, nil
		}
	}

	return CgroupID(0), fmt.Errorf("unknown container id: %s", containerID)
}

func (ts *testState) podsCgroupIDs(t *testing.T, podNames ...string) []uint64 {
	var ret []uint64
	for _, podName := range podNames {
		var p *testPod
		for _, pod := range ts.pods {
			if pod.name == podName {
				p = &pod
				break
			}
		}

		if p == nil {
			t.Fatalf("unknown pod name: %s", podName)
		}

		for _, cont := range p.containers {
			ret = append(ret, uint64(cont.cgID))
		}
	}

	return ret
}

// get cgroup IDs of containers from pods
// podContainerMap is a map of podName -> [podContainerNames]
func (ts *testState) containersCgroupIDs(t *testing.T, podContainerMap map[string][]string) []uint64 {
	var ret []uint64
	for podName, containerNames := range podContainerMap {
		var p *testPod
		for _, pod := range ts.pods {
			if pod.name == podName {
				p = &pod
				break
			}
		}

		if p == nil {
			t.Fatalf("unknown pod name: %s", podName)
		}

		// we create the map to easily understand if the given container name
		// exists. If not, we raise an exception
		existingContainerIDNameMap := make(map[string]uint64)
		for _, cont := range p.containers {
			existingContainerIDNameMap[cont.name] = uint64(cont.cgID)
		}

		for i := range containerNames {
			val, ok := existingContainerIDNameMap[containerNames[i]]
			if !ok {
				t.Fatalf("unknown container name: %s", containerNames[i])
			}
			ret = append(ret, val)
		}
	}

	return ret
}

func testNamespacePods(t *testing.T, st *state, ts *testState) {
	err := st.AddPolicy(PolicyID(2), "ns1", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(3), "ns2", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)

	emptyLabels := labels.Labels{}
	ts.createPod(t, "p1", "ns1", emptyLabels, "p1c1", "p1c2")
	ts.createPod(t, "p2", "ns2", emptyLabels, "p2c1")
	ts.createPod(t, "p3", "ns1", emptyLabels, "p3c1")

	c1 := ts.podsCgroupIDs(t, "p1", "p3")
	c2 := ts.podsCgroupIDs(t, "p2")
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			2:                 c1,
			3:                 c2,
			uint64(AllPodsID): append(c2, c1...),
		},
	)

	ts.deletePod(t, "p3")

	c1 = ts.podsCgroupIDs(t, "p1")
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			2:                 c1,
			3:                 c2,
			uint64(AllPodsID): append(c2, c1...),
		},
	)

	ts.deletePod(t, "p2")
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			2:                 c1,
			3:                 {},
			uint64(AllPodsID): c1,
		},
	)

	err = st.DelPolicy(PolicyID(3))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			2:                 c1,
			uint64(AllPodsID): c1,
		},
	)

	err = st.DelPolicy(PolicyID(2))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(AllPodsID): c1,
		},
	)

	ts.deletePod(t, "p1")
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(AllPodsID): {},
		},
	)
}

func testPodLabelFilters(t *testing.T, st *state, ts *testState) {
	// create policies
	matchesAllID := uint32(2)
	matchesWebID := uint32(3)
	matchesAppsID := uint32(4)
	err := st.AddPolicy(PolicyID(matchesAllID), "", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(matchesWebID), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpIn,
			Values:   []string{"web"},
		}},
	}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(matchesAppsID), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpExists,
		}},
	}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)

	// create pods
	ts.createPod(t, "web", "default", labels.Labels{"app": "web"}, "web-c1", "web-c2")
	ts.createPod(t, "db", "default", labels.Labels{"app": "db"}, "db-c1")
	ts.createPod(t, "log", "default", labels.Labels{}, "log-c1")

	c1 := ts.podsCgroupIDs(t, "web", "db", "log")
	c2 := ts.podsCgroupIDs(t, "web")
	c3 := ts.podsCgroupIDs(t, "web", "db")
	c4 := ts.podsCgroupIDs(t, "db", "log")
	c5 := ts.podsCgroupIDs(t, "db")

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  c1,
			uint64(matchesWebID):  c2,
			uint64(matchesAppsID): c3,
			uint64(AllPodsID):     append(c3, append(c2, c1...)...),
		},
	)

	ts.updatePodLabels(t, "log", labels.Labels{"app": "log"})

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  c1,
			uint64(matchesWebID):  c2,
			uint64(matchesAppsID): c1,
			uint64(AllPodsID):     append(c2, c1...),
		},
	)

	ts.updatePodLabels(t, "web", labels.Labels{"application": "web"})
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  c1,
			uint64(matchesWebID):  {},
			uint64(matchesAppsID): c4,
			uint64(AllPodsID):     append(c4, c1...),
		},
	)

	ts.deletePod(t, "log")
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  c3,
			uint64(matchesWebID):  {},
			uint64(matchesAppsID): c5,
			uint64(AllPodsID):     append(c5, c3...),
		},
	)

	err = st.DelPolicy(PolicyID(matchesAllID))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesWebID):  {},
			uint64(matchesAppsID): c5,
			uint64(AllPodsID):     append(c5, c3...),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	err = st.DelPolicy(PolicyID(matchesAppsID))
	require.NoError(t, err)
	err = st.DelPolicy(PolicyID(matchesWebID))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(AllPodsID): {},
		},
	)
}

func testContainerFieldFilters(t *testing.T, st *state, ts *testState) {
	// create policies
	matchesAllContainers := uint32(2)
	matchesWebContainers := uint32(3)
	matchesNotInitContainers := uint32(4)
	err := st.AddPolicy(PolicyID(matchesAllContainers), "", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(matchesWebContainers), "", &slimv1.LabelSelector{},
		&slimv1.LabelSelector{
			MatchExpressions: []slimv1.LabelSelectorRequirement{{
				Key:      "name",
				Operator: slimv1.LabelSelectorOpIn,
				Values:   []string{"web-c1", "web-c2", "web-c3"},
			}},
		}, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(matchesNotInitContainers), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpIn,
			Values:   []string{"web", "db", "log"},
		}},
	}, &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "name",
			Operator: slimv1.LabelSelectorOpNotIn,
			Values:   []string{"init"},
		}},
	}, nil)
	require.NoError(t, err)

	// create pods
	ts.createPod(t, "web", "default", labels.Labels{"app": "web"}, "web-c1", "web-c2", "init")
	ts.createPod(t, "db", "default", labels.Labels{"app": "db"}, "db-c1")
	ts.createPod(t, "log", "default", labels.Labels{}, "log-c1", "init")

	c1 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c1", "web-c2", "init"},
		"db":  {"db-c1"},
		"log": {"log-c1", "init"},
	})
	c2 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c1", "web-c2"},
	})
	c3 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c1", "web-c2"},
		"db":  {"db-c1"},
		"log": {},
	})

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllContainers): c1,
			uint64(matchesWebContainers): c2,
			// test policy state before we label the log with the matching label
			uint64(matchesNotInitContainers): c3,
			uint64(AllPodsID):                append(c3, append(c2, c1...)...),
		},
	)

	// make sure adding this label will not add all cgroup IDs from the pod to the policy
	ts.updatePodLabels(t, "log", labels.Labels{"app": "log"})
	ts.updatePodContainers(t, "web", "web-c3", "app-c1")

	c4 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3", "app-c1"},
		"db":  {"db-c1"},
		"log": {"log-c1", "init"},
	})
	c5 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3"},
	})
	c6 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3", "app-c1"},
		"db":  {"db-c1"},
		"log": {"log-c1"},
	})

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllContainers):     c4,
			uint64(matchesWebContainers):     c5,
			uint64(matchesNotInitContainers): c6,
			uint64(AllPodsID):                append(c6, append(c5, c4...)...),
		},
	)

	// make sure removing this label will not try to remove all cgroup IDs of this pod from the policy
	// it will not raise an error but there will be a warning
	ts.updatePodLabels(t, "log", labels.Labels{"app": "not-log"})
	ts.updatePodContainers(t, "db", "db-c1", "init")

	c7 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3", "app-c1"},
		"db":  {"db-c1", "init"},
		"log": {"log-c1", "init"},
	})
	c8 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3"},
	})
	c9 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3", "app-c1"},
		"db":  {"db-c1"},
	})

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllContainers):     c7,
			uint64(matchesWebContainers):     c8,
			uint64(matchesNotInitContainers): c9,
			uint64(AllPodsID):                append(c9, append(c8, c7...)...),
		},
	)

	err = st.DelPolicy(PolicyID(matchesAllContainers))
	require.NoError(t, err)
	ts.deletePod(t, "log")

	c10 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3", "app-c1"},
		"db":  {"db-c1", "init"},
	})
	c11 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3"},
	})
	c12 := ts.containersCgroupIDs(t, map[string][]string{
		"web": {"web-c3", "app-c1"},
		"db":  {"db-c1"},
	})

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesWebContainers):     c11,
			uint64(matchesNotInitContainers): c12,
			uint64(AllPodsID):                append(c12, append(c10, c11...)...),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	err = st.DelPolicy(PolicyID(matchesNotInitContainers))
	require.NoError(t, err)
	err = st.DelPolicy(PolicyID(matchesWebContainers))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(AllPodsID): {},
		},
	)
}

func testPreExistingPods(t *testing.T, st *state, ts *testState) {
	// create pods
	ts.createPod(t, "web", "default", labels.Labels{"app": "web"}, "web-c1", "web-c2")
	ts.createPod(t, "db", "default", labels.Labels{"app": "db"}, "db-c1")

	// create policy
	matchesWebID := uint32(2)
	err := st.AddPolicy(PolicyID(matchesWebID), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpIn,
			Values:   []string{"web"},
		}},
	}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)

	c1 := ts.podsCgroupIDs(t, "web")
	c2 := ts.podsCgroupIDs(t, "db")

	require.Len(t, ts.podsCgroupIDs(t, "web"), 2)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesWebID): c1,
			uint64(AllPodsID):    append(c2, c1...),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	err = st.DelPolicy(PolicyID(matchesWebID))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(AllPodsID): {},
		},
	)
}

func testContainersChange(t *testing.T, st *state, ts *testState) {
	ts.createPod(t, "web", "default", nil, "web-c1", "web-c2")
	ts.createPod(t, "db", "default", nil, "db-c1")
	ts.createPod(t, "log", "default", nil, "log-c1")

	// create policy
	policyID := uint32(2)
	err := st.AddPolicy(PolicyID(policyID), "", &slimv1.LabelSelector{},
		&slimv1.LabelSelector{
			MatchExpressions: []slimv1.LabelSelectorRequirement{
				{
					Key:      "name",
					Operator: slimv1.LabelSelectorOpNotIn,
					Values:   []string{"log-c1"},
				}},
		}, nil)
	require.NoError(t, err)

	c1 := ts.podsCgroupIDs(t, "web", "db")
	c2 := ts.podsCgroupIDs(t, "log")

	require.Len(t, ts.podsCgroupIDs(t, "web"), 2)
	require.Len(t, ts.podsCgroupIDs(t, "db"), 1)
	require.Empty(t, ts.containersCgroupIDs(t, map[string][]string{"log": {}}))
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(policyID):  c1,
			uint64(AllPodsID): append(c2, c1...),
		},
	)

	ts.updatePodContainers(t, "web", "web-c1", "web-c3", "web-c4")
	ts.updatePodContainers(t, "db", "db-c2")
	require.Len(t, ts.podsCgroupIDs(t, "web"), 3)
	require.Len(t, ts.podsCgroupIDs(t, "db"), 1)

	c3 := ts.podsCgroupIDs(t, "web", "db")

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(policyID):  c3,
			uint64(AllPodsID): append(c2, c3...),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	ts.deletePod(t, "log")
	err = st.DelPolicy(PolicyID(policyID))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(AllPodsID): {},
		},
	)
}

// TestK8s drives policyfilter through a fake PodEventSource (no informer, no
// fake clientset) and asserts the resulting bpf-map state.
func TestK8s(t *testing.T) {
	// NB: using testutils.CaptureLog causes import cycle
	lc := &tlog{T: t}
	log := slog.New(slog.NewTextHandler(lc, nil))
	logger.DefaultSlogLogger = log

	oldEnablePolicyFilterValue := option.Config.EnablePolicyFilter
	oldEnablePolicyFilterValueDebug := option.Config.EnablePolicyFilterDebug
	option.Config.EnablePolicyFilter = true
	option.Config.EnablePolicyFilterDebug = false
	t.Cleanup(func() {
		option.Config.EnablePolicyFilter = oldEnablePolicyFilterValue
		option.Config.EnablePolicyFilterDebug = oldEnablePolicyFilterValueDebug
	})

	source := &fakePodEventSource{}
	ts := newTestState(source)
	st, err := newState(log, ts, true)
	if err != nil {
		t.Skipf("failed to initialize policy filter state: %s", err)
	}
	defer st.Close()

	st.RegisterPodHandlers(source)

	t.Run("namespaces", func(t *testing.T) {
		testNamespacePods(t, st, ts)
	})

	t.Run("pod labels", func(t *testing.T) {
		testPodLabelFilters(t, st, ts)
	})

	t.Run("container fields", func(t *testing.T) {
		testContainerFieldFilters(t, st, ts)
	})

	t.Run("pre-existing pods", func(t *testing.T) {
		testPreExistingPods(t, st, ts)
	})

	t.Run("containers change", func(t *testing.T) {
		testContainersChange(t, st, ts)
	})
}
