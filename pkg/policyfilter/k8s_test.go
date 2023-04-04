package policyfilter

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

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

type tlog struct {
	*testing.T
	Log *logrus.Logger
}

func (tl tlog) Write(p []byte) (n int, err error) {
	tl.Logf((string)(p))
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
			ts.cbAdds.Add(1)
			h.OnAdd(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ts.cbUpds.Add(1)
			h.OnUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			ts.cbDels.Add(1)
			h.OnDelete(obj)
		},
	}
}

func (ts *testState) createPod(t *testing.T, name string, namespace string, containerNames ...string) {
	podID := uuid.New()
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			UID:       k8stypes.UID(podID.String()),
			Namespace: namespace},
		Spec:   v1.PodSpec{},
		Status: v1.PodStatus{},
	}
	testPod := testPod{
		name:      name,
		id:        podID,
		namespace: namespace,
	}

	for _, contName := range containerNames {
		contID := fmt.Sprintf("%s-%s", contName, ts.randString(8))
		pod.Spec.Containers = append(pod.Spec.Containers, v1.Container{
			Name: contName,
		})
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, v1.ContainerStatus{
			Name:        contName,
			ContainerID: contID,
		})

		testPod.containers = append(testPod.containers, testContainer{
			name: contName,
			id:   contID,
			cgID: CgroupID(ts.rnd.Uint64()),
		})
	}

	ts.pods = append(ts.pods, testPod)

	_, err := ts.client.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error injecting pod add: %v", err)
	}
	ts.nrAdds += 1
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

	ts.nrDels += 1
}

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

// example taken from https://github.com/kubernetes/client-go/blob/04ef61f72b7bc5ae6efef4e4dc0001746637fdb3/examples/fake-client/main_test.go
func TestK8s(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// NB: using testutils.CaptureLog causes import cycle
	log := logger.GetLogger().(*logrus.Logger)
	lc := &tlog{T: t, Log: log}
	log.SetOutput(lc)

	oldEnablePolicyFilterValue := option.Config.EnablePolicyFilter
	option.Config.EnablePolicyFilter = true
	t.Cleanup(func() {
		option.Config.EnablePolicyFilter = oldEnablePolicyFilterValue
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

	ts := testState{
		client: client,
		rnd:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	st, err := newState(log, &ts)
	if err != nil {
		t.Skip(fmt.Sprintf("failed to initialize policy filter state: %s", err))
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

	t.Run("namespaced pods", func(t *testing.T) {
		err = st.AddPolicy(PolicyID(1), "ns1", nil)
		require.NoError(t, err)
		err = st.AddPolicy(PolicyID(2), "ns2", nil)
		require.NoError(t, err)

		ts.createPod(t, "p1", "ns1", "p1c1", "p1c2")
		ts.createPod(t, "p2", "ns2", "p2c1")
		ts.createPod(t, "p3", "ns1", "p3c1")
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
	})
}
