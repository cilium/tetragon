// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package podinfo

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	random "math/rand"
	"testing"

	ciliumv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func getRandString(length int) string {
	b := make([]rune, length)
	for i := range b {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letterRunes))))
		b[i] = letterRunes[index.Int64()]
	}
	return string(b)
}

// randNum generates a random number between 1 to 10
func getRandNum() int {
	return random.Intn(10) + 1
}

// getRandMap returns a random map of string that can be used a labels and annotations.
func getRandMap() map[string]string {
	labels := map[string]string{}
	mapLength := getRandNum()
	keyLength := getRandNum()
	valueLength := getRandNum()

	for i := 0; i <= mapLength; i++ {
		key := getRandString(keyLength)
		value := getRandString(valueLength)
		labels[key] = value
	}
	return labels
}

// getRandIP returns a random string that can be used an IP address.
func getRandIP() string {
	randIP := fmt.Sprintf("10.%d.%d.%d", getRandNum(), getRandNum(), getRandNum())
	return randIP
}

// getRandIPs returns an array of string which can be used as PodIPs field.
func getRandIPs() (string, []string) {
	length := getRandNum() + 1
	podIPs := make([]string, length)
	for i := 0; i < length; i++ {
		podIPs[i] = getRandIP()
	}
	return podIPs[0], podIPs
}

// randomPodGenerator generates a random Kubernetes Pod.
func randomPodGenerator() *corev1.Pod {
	randIP, randIPs := getRandIPs()

	randPodIPs := make([]corev1.PodIP, len(randIPs))
	for i, item := range randIPs {
		randPodIPs[i] = corev1.PodIP{IP: item}
	}

	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        getRandString(getRandNum()),
			Namespace:   "default",
			Labels:      getRandMap(),
			Annotations: getRandMap(),
			UID:         uuid.NewUUID(),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "nginx:latest",
				},
			},
			NodeName: getRandString(5),
		},
		Status: corev1.PodStatus{
			PodIP:  randIP,
			PodIPs: randPodIPs,
		},
	}

	return pod
}

// TestGeneratePod tests if the corresponding podInfo CR generated for a pod is same when using generatePodInfo function
func TestGeneratePod(t *testing.T) {
	t.Run("Testing Object Meta", func(t *testing.T) {
		pod := randomPodGenerator()
		controller := true
		blockOwnerDeletion := true
		// Copy the Pod IPs into the PodInfo IPs.
		var podIPs []ciliumv1alpha1.PodIP
		for _, podIP := range pod.Status.PodIPs {
			podIPs = append(podIPs, ciliumv1alpha1.PodIP{IP: podIP.IP})
		}
		workloadObject, workloadType := podhelpers.GetWorkloadMetaFromPod(pod)
		expectedPodInfo := &ciliumv1alpha1.PodInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:        pod.Name,
				Namespace:   pod.Namespace,
				Labels:      pod.Labels,
				Annotations: pod.Annotations,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         pod.APIVersion,
						Kind:               pod.Kind,
						Name:               pod.Name,
						UID:                pod.UID,
						Controller:         &controller,
						BlockOwnerDeletion: &blockOwnerDeletion,
					},
				},
			},
			Spec: ciliumv1alpha1.PodInfoSpec{
				NodeName: pod.Spec.NodeName,
			},
			Status: ciliumv1alpha1.PodInfoStatus{
				PodIP:  pod.Status.PodIP,
				PodIPs: podIPs,
			},
			WorkloadType:   workloadType,
			WorkloadObject: workloadObject,
		}
		generatedPodInfo := generatePodInfo(pod)
		assert.Equal(t, expectedPodInfo, generatedPodInfo, "Generated incorrect PodInfo corresponding to the pod")
	})
}

// TestHasAllRequiredFields checks if a pod is ready or not.
func TestHasAllRequiredFields(t *testing.T) {
	t.Run("Check if all the necessary fields of pod are available", func(t *testing.T) {

		// test ready pod.
		t.Run("All fields available", func(*testing.T) {
			pod := randomPodGenerator()
			assert.True(t, hasAllRequiredFields(pod), "All fields are available still function returns false")
		})

		// test non-ready pods.
		t.Run("Name not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Name = ""
			assert.False(t, hasAllRequiredFields(pod), "Name not available still returning Pod to be ready")
		})

		t.Run("Namespace not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Namespace = ""
			assert.False(t, hasAllRequiredFields(pod), "Namespace not available still returning Pod to be ready")
		})

		t.Run("Pod IP not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Status.PodIP = ""
			assert.False(t, hasAllRequiredFields(pod), "Pod IP not available still returning Pod to be ready")
		})

		t.Run("Pod IPs not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Status.PodIPs = nil
			assert.False(t, hasAllRequiredFields(pod), "Pod IPs not available still returning Pod to be ready")
		})

		t.Run("Pod UID not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.UID = ""
			assert.False(t, hasAllRequiredFields(pod), "Pod UID not available still returning Pod to be ready")
		})

		t.Run("Pod NodeName not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Spec.NodeName = ""
			assert.False(t, hasAllRequiredFields(pod), "Pod NodeName not available still returning Pod to be ready")
		})

	})
}

// TestEqual checks if controller function checkIfChanged returns true if the Pod is changed and false if it did not change.
func TestEqual(t *testing.T) {
	t.Run("Check if the pod and podInfo are different", func(t *testing.T) {
		// All fields match
		t.Run("All fields same", func(*testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			assert.True(t, equal(pod, podInfo), "All fields match, still returning pod to be changed")
		})

		// Fields mismatch
		t.Run("Pod Name changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			pod.Name = getRandString(getRandNum())
			assert.False(t, equal(pod, podInfo), "Pod Name changed, still returning pod not changed")
		})

		t.Run("Pod Namespace changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			pod.Namespace = getRandString(getRandNum())

			assert.False(t, equal(pod, podInfo), "Pod Namespace changed, still returning pod not changed")
		})

		t.Run("Pod IP changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			pod.Status.PodIP = "20.0.0.1"
			assert.False(t, equal(pod, podInfo), "Pod IP changed, still returning pod not changed")
		})

		t.Run("Pod IPs changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			randIP, randIPs := getRandIPs()

			randPodIPs := make([]corev1.PodIP, len(randIPs))
			for i, IP := range randIPs {
				randPodIPs[i] = corev1.PodIP{IP: IP}
			}
			pod.Status.PodIP = randIP
			pod.Status.PodIPs = randPodIPs

			assert.False(t, equal(pod, podInfo), "Pod IPs changed, still returning pod not changed")
		})

		t.Run("Pod Labels changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			pod.Labels = getRandMap()
			assert.False(t, equal(pod, podInfo), "Pod Labels changed, still returning pod not changed")
		})

		t.Run("Pod annotations changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			pod.Annotations = getRandMap()
			assert.False(t, equal(pod, podInfo), "Pod Annotations changed, still returning pod not changed")
		})

		t.Run("Pod owner references changed", func(t *testing.T) {
			pod := randomPodGenerator()
			controller, blockOwnerDeletion := true, true
			podInfo := generatePodInfo(pod)
			pod.GenerateName = "tetragon-"
			pod.OwnerReferences = []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "DaemonSet",
					Name:               "tetragon",
					UID:                "00000000-0000-0000-0000-000000000000",
					Controller:         &controller,
					BlockOwnerDeletion: &blockOwnerDeletion,
				},
			}
			assert.False(t, equal(pod, podInfo), "Pod owner references changed, still returning pod not changed")
		})

		t.Run("Pod spec hostNetwork changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			pod.Spec.HostNetwork = true
			assert.False(t, equal(pod, podInfo), "Pod spec hostNetwork changed, still returning pod not changed")
		})

		t.Run("Pod spec nodeName changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := generatePodInfo(pod)
			pod.Spec.NodeName = getRandString(4)
			assert.False(t, equal(pod, podInfo), "Pod spec nodeName changed, still returning pod not changed")
		})
	})
}

func TestReconcile(t *testing.T) {
	pod := randomPodGenerator()
	client := getClientBuilder().WithObjects(pod).Build()
	reconciler := Reconciler{client}
	namespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	res, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	assert.NoError(t, err)
	assert.False(t, res.Requeue)
	assert.NoError(t, client.Get(context.Background(), namespacedName, &ciliumv1alpha1.PodInfo{}))
}

func TestReconcileWithDeletionTimestamp(t *testing.T) {
	pod := randomPodGenerator()
	pod.SetFinalizers([]string{"finalize-it"})
	deletionTimestamp := metav1.Now()
	pod.SetDeletionTimestamp(&deletionTimestamp)
	client := getClientBuilder().WithObjects(pod).Build()
	reconciler := Reconciler{client}
	namespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	res, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	assert.NoError(t, err)
	assert.False(t, res.Requeue)
	err = client.Get(context.Background(), namespacedName, &ciliumv1alpha1.PodInfo{})
	assert.True(t, errors.IsNotFound(err))
}

func getClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(ciliumv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme)
}
