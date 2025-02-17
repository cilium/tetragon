// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

type tlog struct {
	*testing.T
	Logger *logrus.Logger
}

func (tl tlog) Write(p []byte) (n int, err error) {
	tl.Log(string(p))
	return len(p), nil
}

// This test tests that we can still do pod association when a pod is removed from the k8s cache
// (effectively, this tests the deleted pod cache feature).
func TestFastK8s(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// NB: using testutils.CaptureLog causes import cycle
	log := logger.GetLogger().(*logrus.Logger)
	lc := &tlog{T: t, Logger: log}
	log.SetOutput(lc)

	// example taken from https://github.com/kubernetes/client-go/blob/04ef61f72b7bc5ae6efef4e4dc0001746637fdb3/examples/fake-client/main_test.go
	watcherStarted := make(chan struct{})
	// Create the fake client.
	client := k8sfake.NewSimpleClientset()

	// create test state
	ts := testState{
		client: client,
	}

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
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	podInformer := informerFactory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(ts.eventHandler())

	watcher, err := newK8sWatcher(informerFactory)
	require.Nil(t, err)
	watcher.Start()

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

	namespace := "ns1"
	t.Log("adding pod")
	ts.createPod(t, namespace, "mypod", "mycontainer")

	ts.waitForCallbacks(t)
	pod, _, found := watcher.FindContainer(contIDFromName("mycontainer"))
	require.True(t, found, "added pod should be found")
	require.Equal(t, pod.Name, "mypod")

	t.Log("deleting pod")
	ts.deletePod(t, namespace, "mypod")

	ts.waitForCallbacks(t)
	pod, _, found = watcher.FindContainer(contIDFromName("mycontainer"))
	require.True(t, found, "deleted pod should be found")
	require.Equal(t, pod.Name, "mypod")
}

type testContainer struct {
	name string
	id   string
}

type testPod struct {
	name       string
	id         uuid.UUID
	namespace  string
	containers []testContainer
}

func (tp *testPod) Pod() *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tp.name,
			UID:       k8stypes.UID(tp.id.String()),
			Namespace: tp.namespace,
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

type testState struct {
	// number of pod adds/deletes
	nrAdds, nrDels atomic.Uint64
	// number of callbacks being called for pods adds/deletes
	cbAdds, cbDels atomic.Uint64

	client *fake.Clientset
}

func contIDFromName(s string) string {
	return fmt.Sprintf("cont-id-%s", s)
}

func (ts *testState) createPod(t *testing.T, namespace string, name string, containerNames ...string) {
	podID := uuid.New()
	testPod := testPod{
		name:      name,
		id:        podID,
		namespace: namespace,
	}

	for _, contName := range containerNames {
		testPod.containers = append(testPod.containers, testContainer{
			name: contName,
			id:   "docker://" + contIDFromName(contName),
		})
	}

	pod := testPod.Pod()
	_, err := ts.client.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	require.Nil(t, err, "failed to create pod")
	ts.nrAdds.Add(1)
}

func (ts *testState) deletePod(t *testing.T, namespace string, name string) {
	err := ts.client.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	require.Nil(t, err, "failed to delete pod")
	ts.nrDels.Add(1)
}

func (ts *testState) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(_ interface{}) {
			ts.cbAdds.Add(1)
		},
		DeleteFunc: func(_ interface{}) {
			ts.cbDels.Add(1)
		},
	}
}

func (ts *testState) callbacksDone() bool {
	return (ts.cbAdds.Load() == ts.nrAdds.Load()) &&
		(ts.cbDels.Load() == ts.nrDels.Load())
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
