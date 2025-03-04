// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policyfilter

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

// Testing of policyfilter using a fake k8s clientset.
//
// The idea here is to perform k8s operations that cause our callbacks to be called, and then test
// the state of the policyfilter bpf map.
//
// There are a few complications:
// We need a fake cgroup-id finder that can map container ids to cgroup ids.
// Since the pod informer callbacks are called asynchronously, we need to know were they have been
// called so that test whether the state is up-to-date. To this end, we wrap the callbacks and
// implement counters that we check before testing the state (see waitForCallbacks).
//
// The approach here can be extended for randomized testing by having a (simpler) mirrored state and
// performing state transitions and checking that each step is correct.

type tlog struct {
	*testing.T
	Logger *logrus.Logger
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
	return fmt.Sprintf("%x", b)[2 : length+2]
}

// testState provides two things: i) helper functions for creating/updating pods, and ii) a fake
// FsScanner.
type testState struct {
	pods   []testPod
	client *fake.Clientset
	rnd    *rand.Rand

	nrAdds, nrUpds, nrDels uint64
	cbAdds, cbUpds, cbDels atomic.Uint64
}

func newTestState(client *fake.Clientset) *testState {
	ts := testState{
		client: client,
		rnd:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	return &ts
}

func (ts *testState) callbacksDone() bool {
	return (ts.cbAdds.Load() == ts.nrAdds) &&
		(ts.cbUpds.Load() == ts.nrUpds) &&
		(ts.cbDels.Load() == ts.nrDels)
}

func (ts *testState) waitForCallbacks(t *testing.T) {
	dt := 1 * time.Millisecond
	for i := 0; i < 6; i++ {
		time.Sleep(dt)
		if ts.callbacksDone() {
			return
		}
		dt = 5 * dt
	}

	t.Fatalf("waitForCallbacks: timeout (%s)", dt)
}

func (ts *testState) eventHandler(m *state) cache.ResourceEventHandler {
	h := m.getPodEventHandlers()
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			h.OnAdd(obj, false)
			ts.cbAdds.Add(1)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			h.OnUpdate(oldObj, newObj)
			ts.cbUpds.Add(1)
		},
		DeleteFunc: func(obj interface{}) {
			h.OnDelete(obj)
			ts.cbDels.Add(1)
		},
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

func (ts *testState) createPod(t *testing.T, name string, namespace string, podLabels labels.Labels, containerNames ...string) {
	podID := uuid.New()
	testPod := testPod{
		name:      name,
		id:        podID,
		namespace: namespace,
		labels:    podLabels,
	}

	for _, contName := range containerNames {
		testPod.containers = append(testPod.containers, ts.newTestContainer(contName))
	}
	ts.pods = append(ts.pods, testPod)

	pod := testPod.Pod()
	_, err := ts.client.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error injecting pod add: %v", err)
	}
	ts.nrAdds++
}

func (ts *testState) findPod(t *testing.T, name string) *testPod {
	var testPod *testPod
	for i := range ts.pods {
		if ts.pods[i].name == name {
			testPod = &ts.pods[i]
		}
	}
	require.NotNil(t, testPod)
	return testPod
}

func (ts *testState) updatePodContainers(t *testing.T, name string, containerNames ...string) {
	testPod := ts.findPod(t, name)
	containers := map[string]testContainer{}
	for _, cont := range testPod.containers {
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
	testPod.containers = newContainers

	pod := testPod.Pod()
	_, err := ts.client.CoreV1().Pods(testPod.namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error injecting pod update: %v", err)
	}
	ts.nrUpds++
}

func (ts *testState) updatePodLabels(t *testing.T, name string, podLabels labels.Labels) {
	testPod := ts.findPod(t, name)
	testPod.labels = podLabels
	pod := testPod.Pod()
	_, err := ts.client.CoreV1().Pods(testPod.namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error injecting pod update: %v", err)
	}
	ts.nrUpds++
}

func (ts *testState) deletePod(t *testing.T, name string) {
	var p *testPod
	for idx, pod := range ts.pods {
		if pod.name == name {
			p = &pod
			ts.pods = append(ts.pods[:idx], ts.pods[idx+1:]...)
			break
		}
	}
	if p == nil {
		t.Fatalf("unknown pod name: %s", name)
	}
	err := ts.client.CoreV1().Pods(p.namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("error deleting pod %s: %v", name, err)
	}
	ts.nrDels++
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
	err := st.AddPolicy(PolicyID(1), "ns1", nil, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(2), "ns2", nil, nil)
	require.NoError(t, err)

	emptyLabels := labels.Labels{}
	ts.createPod(t, "p1", "ns1", emptyLabels, "p1c1", "p1c2")
	ts.createPod(t, "p2", "ns2", emptyLabels, "p2c1")
	ts.createPod(t, "p3", "ns1", emptyLabels, "p3c1")
	ts.waitForCallbacks(t)

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			1: ts.podsCgroupIDs(t, "p1", "p3"),
			2: ts.podsCgroupIDs(t, "p2"),
		},
	)

	ts.deletePod(t, "p3")
	ts.waitForCallbacks(t)

	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			1: ts.podsCgroupIDs(t, "p1"),
			2: ts.podsCgroupIDs(t, "p2"),
		},
	)

	ts.deletePod(t, "p2")
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			1: ts.podsCgroupIDs(t, "p1"),
			2: {},
		},
	)

	err = st.DelPolicy(PolicyID(2))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			1: ts.podsCgroupIDs(t, "p1"),
		},
	)

	err = st.DelPolicy(PolicyID(1))
	require.NoError(t, err)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{},
	)

	ts.deletePod(t, "p1")
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{},
	)
}

func testPodLabelFilters(t *testing.T, st *state, ts *testState) {
	// create policies
	matchesAllID := uint32(1)
	matchesWebID := uint32(2)
	matchesAppsID := uint32(3)
	err := st.AddPolicy(PolicyID(matchesAllID), "", nil, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(matchesWebID), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpIn,
			Values:   []string{"web"},
		}},
	}, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(matchesAppsID), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpExists,
		}},
	}, nil)
	require.NoError(t, err)

	// create pods
	ts.createPod(t, "web", "default", labels.Labels{"app": "web"}, "web-c1", "web-c2")
	ts.createPod(t, "db", "default", labels.Labels{"app": "db"}, "db-c1")
	ts.createPod(t, "log", "default", labels.Labels{}, "log-c1")

	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  ts.podsCgroupIDs(t, "web", "db", "log"),
			uint64(matchesWebID):  ts.podsCgroupIDs(t, "web"),
			uint64(matchesAppsID): ts.podsCgroupIDs(t, "web", "db"),
		},
	)

	ts.updatePodLabels(t, "log", labels.Labels{"app": "log"})

	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  ts.podsCgroupIDs(t, "web", "db", "log"),
			uint64(matchesWebID):  ts.podsCgroupIDs(t, "web"),
			uint64(matchesAppsID): ts.podsCgroupIDs(t, "web", "db", "log"),
		},
	)

	ts.updatePodLabels(t, "web", labels.Labels{"application": "web"})
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  ts.podsCgroupIDs(t, "web", "db", "log"),
			uint64(matchesWebID):  ts.podsCgroupIDs(t),
			uint64(matchesAppsID): ts.podsCgroupIDs(t, "db", "log"),
		},
	)

	ts.deletePod(t, "log")
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllID):  ts.podsCgroupIDs(t, "web", "db"),
			uint64(matchesWebID):  ts.podsCgroupIDs(t),
			uint64(matchesAppsID): ts.podsCgroupIDs(t, "db"),
		},
	)

	err = st.DelPolicy(PolicyID(matchesAllID))
	require.NoError(t, err)
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesWebID):  ts.podsCgroupIDs(t),
			uint64(matchesAppsID): ts.podsCgroupIDs(t, "db"),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	err = st.DelPolicy(PolicyID(matchesAppsID))
	require.NoError(t, err)
	err = st.DelPolicy(PolicyID(matchesWebID))
	require.NoError(t, err)
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{},
	)
}

func testContainerFieldFilters(t *testing.T, st *state, ts *testState) {
	// create policies
	matchesAllContainers := uint32(1)
	matchesWebContainers := uint32(2)
	matchesNotInitContainers := uint32(3)
	err := st.AddPolicy(PolicyID(matchesAllContainers), "", nil, nil)
	require.NoError(t, err)
	err = st.AddPolicy(PolicyID(matchesWebContainers), "", nil,
		&slimv1.LabelSelector{
			MatchExpressions: []slimv1.LabelSelectorRequirement{{
				Key:      "name",
				Operator: slimv1.LabelSelectorOpIn,
				Values:   []string{"web-c1", "web-c2", "web-c3"},
			}},
		})
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
	})
	require.NoError(t, err)

	// create pods
	ts.createPod(t, "web", "default", labels.Labels{"app": "web"}, "web-c1", "web-c2", "init")
	ts.createPod(t, "db", "default", labels.Labels{"app": "db"}, "db-c1")
	ts.createPod(t, "log", "default", labels.Labels{}, "log-c1", "init")

	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c1", "web-c2", "init"},
				"db":  {"db-c1"},
				"log": {"log-c1", "init"},
			}),
			uint64(matchesWebContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c1", "web-c2"},
			}),
			// test policy state before we label the log with the matching label
			uint64(matchesNotInitContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c1", "web-c2"},
				"db":  {"db-c1"},
				"log": {},
			}),
		},
	)

	// make sure adding this label will not add all cgroup IDs from the pod to the policy
	ts.updatePodLabels(t, "log", labels.Labels{"app": "log"})
	ts.updatePodContainers(t, "web", "web-c3", "app-c1")
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3", "app-c1"},
				"db":  {"db-c1"},
				"log": {"log-c1", "init"},
			}),
			uint64(matchesWebContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3"},
			}),
			uint64(matchesNotInitContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3", "app-c1"},
				"db":  {"db-c1"},
				"log": {"log-c1"},
			}),
		},
	)

	// make sure removing this label will not try to remove all cgroup IDs of this pod from the policy
	// it will not raise an error but there will be a warning
	ts.updatePodLabels(t, "log", labels.Labels{"app": "not-log"})
	ts.updatePodContainers(t, "db", "db-c1", "init")
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesAllContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3", "app-c1"},
				"db":  {"db-c1", "init"},
				"log": {"log-c1", "init"},
			}),
			uint64(matchesWebContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3"},
			}),
			uint64(matchesNotInitContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3", "app-c1"},
				"db":  {"db-c1"},
			}),
		},
	)

	err = st.DelPolicy(PolicyID(matchesAllContainers))
	require.NoError(t, err)
	ts.deletePod(t, "log")
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesWebContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3"},
			}),
			uint64(matchesNotInitContainers): ts.containersCgroupIDs(t, map[string][]string{
				"web": {"web-c3", "app-c1"},
				"db":  {"db-c1"},
			}),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	err = st.DelPolicy(PolicyID(matchesNotInitContainers))
	require.NoError(t, err)
	err = st.DelPolicy(PolicyID(matchesWebContainers))
	require.NoError(t, err)
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{},
	)
}

func testPreExistingPods(t *testing.T, st *state, ts *testState) {
	// create pods
	ts.createPod(t, "web", "default", labels.Labels{"app": "web"}, "web-c1", "web-c2")
	ts.createPod(t, "db", "default", labels.Labels{"app": "db"}, "db-c1")
	ts.waitForCallbacks(t)

	// create policy
	matchesWebID := uint32(2)
	err := st.AddPolicy(PolicyID(matchesWebID), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpIn,
			Values:   []string{"web"},
		}},
	}, nil)
	require.NoError(t, err)

	require.Equal(t, len(ts.podsCgroupIDs(t, "web")), 2)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(matchesWebID): ts.podsCgroupIDs(t, "web"),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	err = st.DelPolicy(PolicyID(matchesWebID))
	require.NoError(t, err)
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{},
	)
}

func testContainersChange(t *testing.T, st *state, ts *testState) {
	ts.createPod(t, "web", "default", nil, "web-c1", "web-c2")
	ts.createPod(t, "db", "default", nil, "db-c1")
	ts.createPod(t, "log", "default", nil, "log-c1")
	ts.waitForCallbacks(t)

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
		})
	require.NoError(t, err)

	require.Equal(t, len(ts.podsCgroupIDs(t, "web")), 2)
	require.Equal(t, len(ts.podsCgroupIDs(t, "db")), 1)
	require.Equal(t, len(ts.containersCgroupIDs(t, map[string][]string{"log": {}})), 0)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(policyID): ts.podsCgroupIDs(t, "web", "db"),
		},
	)

	ts.updatePodContainers(t, "web", "web-c1", "web-c3", "web-c4")
	ts.updatePodContainers(t, "db", "db-c2")
	require.Equal(t, len(ts.podsCgroupIDs(t, "web")), 3)
	require.Equal(t, len(ts.podsCgroupIDs(t, "db")), 1)
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{
			uint64(policyID): ts.podsCgroupIDs(t, "web", "db"),
		},
	)

	ts.deletePod(t, "web")
	ts.deletePod(t, "db")
	ts.deletePod(t, "log")
	err = st.DelPolicy(PolicyID(policyID))
	require.NoError(t, err)
	ts.waitForCallbacks(t)
	requirePfmEqualTo(t, st.pfMap,
		map[uint64][]uint64{},
	)
}

// example taken from https://github.com/kubernetes/client-go/blob/04ef61f72b7bc5ae6efef4e4dc0001746637fdb3/examples/fake-client/main_test.go
func TestK8s(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// NB: using testutils.CaptureLog causes import cycle
	log := logger.GetLogger().(*logrus.Logger)
	lc := &tlog{T: t, Logger: log}
	log.SetOutput(lc)

	oldEnablePolicyFilterValue := option.Config.EnablePolicyFilter
	oldEnablePolicyFilterValueDebug := option.Config.EnablePolicyFilterDebug
	option.Config.EnablePolicyFilter = true
	option.Config.EnablePolicyFilterDebug = false
	t.Cleanup(func() {
		option.Config.EnablePolicyFilter = oldEnablePolicyFilterValue
		option.Config.EnablePolicyFilterDebug = oldEnablePolicyFilterValueDebug
	})

	watcherStarted := make(chan struct{})
	// Create the fake client.
	client := fake.NewSimpleClientset()
	// A catch-all watch reactor that allows us to inject the watcherStarted channel.
	client.PrependWatchReactor("*", func(action clienttesting.Action) (handled bool, ret watch.Interface, err error) {
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := client.Tracker().Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		close(watcherStarted)
		return true, watch, nil
	})

	// We will create an informer that writes added pods to a channel.
	informers := informers.NewSharedInformerFactory(client, 0)
	podInformer := informers.Core().V1().Pods().Informer()

	// testState implements cgFinder
	ts := newTestState(client)
	st, err := newState(log, ts, true)
	if err != nil {
		t.Skipf("failed to initialize policy filter state: %s", err)
	}
	defer st.Close()

	podInformer.AddEventHandler(ts.eventHandler(st))

	// Make sure informers are running.
	informers.Start(ctx.Done())

	// This is not required in tests, but it serves as a proof-of-concept by
	// ensuring that the informer goroutine have warmed up and called List before
	// we send any events to it.
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)

	// The fake client doesn't support resource version. Any writes to the client
	// after the informer's initial LIST and before the informer establishing the
	// watcher will be missed by the informer. Therefore we wait until the watcher
	// starts.
	// Note that the fake client isn't designed to work with informer. It
	// doesn't support resource version. It's encouraged to use a real client
	// in an integration/E2E test if you need to test complex behavior with
	// informer/controllers.
	<-watcherStarted

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
