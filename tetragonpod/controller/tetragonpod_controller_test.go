package controller

import (
	"crypto/rand"
	"fmt"
	ciliumiov1alpha1 "github.com/cilium/tetragon/tetragonpod/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"math/big"
	random "math/rand"
	"reflect"
	"testing"
)

// Things I should be testing.
// - Name matches
// - Namespace
// - Labels
// - Annotations
// - OwnerReference
// - PodIP
// 		- single pod IP so they should match. and PodIPs array should also match.
// - PodIPs
// 		- Multiple PodIPs should match perfectly.
// - Current Pod IP should be same as 0th index of pod.

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

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

//// printPod prints the pod
//func printPod(pod *corev1.Pod) {
//	fmt.Printf("Pod:\n")
//	fmt.Printf("  Kind: %s\n", pod.Kind)
//	fmt.Printf("  API Version: %s\n", pod.APIVersion)
//	fmt.Printf("  Metadata:\n")
//	fmt.Printf("    Name: %s\n", pod.Name)
//	fmt.Printf("    Namespace: %s\n", pod.Namespace)
//	fmt.Printf("    UID: %s\n", pod.UID)
//	fmt.Printf("    Labels: %v\n", pod.Labels)
//	fmt.Printf("    Annotations: %v\n", pod.Annotations)
//	fmt.Printf("  Status:\n")
//	fmt.Printf("    Pod IP: %s\n", pod.Status.PodIP)
//	fmt.Printf("    Pod IPs:\n")
//	for _, ip := range pod.Status.PodIPs {
//		fmt.Printf("      IP: %s\n", ip.IP)
//	}
//}
//
//func printPodInfo(podInfo *ciliumiov1alpha1.TetragonPod) {
//	fmt.Println("Pod Information:")
//	fmt.Printf("  Name: %s\n", podInfo.Name)
//	fmt.Printf("  Namespace: %s\n", podInfo.Namespace)
//	fmt.Printf("  Labels: %v\n", podInfo.Labels)
//	fmt.Printf("  Annotations: %v\n", podInfo.Annotations)
//
//	fmt.Println("Owner References:")
//	for _, ownerRef := range podInfo.OwnerReferences {
//		fmt.Printf("  API Version: %s\n", ownerRef.APIVersion)
//		fmt.Printf("  Kind: %s\n", ownerRef.Kind)
//		fmt.Printf("  Name: %s\n", ownerRef.Name)
//		fmt.Printf("  UID: %s\n", ownerRef.UID)
//	}
//
//	fmt.Println("Status:")
//	fmt.Printf("  Pod IP: %s\n", podInfo.Status.PodIP)
//	fmt.Println("  Pod IPs:")
//	for _, ip := range podInfo.Status.PodIPs {
//		fmt.Printf("    IP: %s\n", ip.IP)
//	}
//}

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

func getRandIP() string {
	randIP := fmt.Sprintf("10.%d.%d.%d", getRandNum(), getRandNum(), getRandNum())
	return randIP
}

func getRandIPs() (string, []string) {
	// firstIP := getRandIP()
	length := getRandNum() + 1
	podIPs := make([]string, length)
	for i := 0; i < length; i++ {
		podIPs[i] = getRandIP()
	}
	return podIPs[0], podIPs
}

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
			Namespace:   getRandString(getRandNum()),
			UID:         uuid.NewUUID(),
			Labels:      getRandMap(),
			Annotations: getRandMap(),
		},
		// need to implement the logic of generating random IPs
		Status: corev1.PodStatus{
			PodIP:  randIP,
			PodIPs: randPodIPs,
		},
	}

	return pod
}

func getPodInfo(pod *corev1.Pod) *ciliumiov1alpha1.TetragonPod {
	podIPs := []ciliumiov1alpha1.PodIP{}
	for _, podIP := range pod.Status.PodIPs {
		podIPs = append(podIPs, ciliumiov1alpha1.PodIP{IP: podIP.IP})
	}

	podInfo := &ciliumiov1alpha1.TetragonPod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			Labels:      pod.Labels,
			Annotations: pod.Annotations,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: pod.APIVersion,
					Kind:       pod.Kind,
					Name:       pod.Name,
					UID:        pod.UID,
				},
			},
		},
		Status: ciliumiov1alpha1.TetragonPodStatus{
			PodIP:  pod.Status.PodIP,
			PodIPs: podIPs,
		},
	}

	return podInfo
}

//func getRandomPodInfo() *ciliumiov1alpha1.TetragonPod {
//	podInfo := &ciliumiov1alpha1.TetragonPod{
//		ObjectMeta: metav1.ObjectMeta{
//			Name:        getRandString(getRandNum()),
//			Namespace:   getRandString(getRandNum()),
//			Labels:      getRandMap(),
//			Annotations: getRandMap(),
//			OwnerReferences: []metav1.OwnerReference{
//				{
//					APIVersion: getRandString(getRandNum()),
//					Kind:       getRandString(getRandNum()),
//					Name:       getRandString(getRandNum()),
//					UID:        uuid.NewUUID(),
//				},
//			},
//		},
//		Status: ciliumiov1alpha1.TetragonPodStatus{
//			PodIP:  ,
//			PodIPs: podIPs,
//		},
//	}
//
//	return podInfo
//}

// TestGeneratePod tests if the corresponding podInfo CR generated for a pod is same when using generatePod function
func TestGeneratePod(t *testing.T) {
	t.Run("Testing Object Meta", func(t *testing.T) {
		pod := randomPodGenerator()
		expectedPodInfo := getPodInfo(pod)
		generatedPodInfo := generatePod(pod)

		assert.True(t, reflect.DeepEqual(expectedPodInfo, generatedPodInfo), "Generated incorrect PodInfo corresponding to te pod")
	})
}

func TestCheckIfReady(t *testing.T) {
	t.Run("Check if all the necessary fields of pod are available", func(t *testing.T) {

		// test ready pod.
		t.Run("All fields available", func(*testing.T) {
			pod := randomPodGenerator()
			assert.True(t, checkIfReady(pod), "All fields are available still function returns false")
		})

		// test non-ready pods.
		t.Run("Name not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Name = ""
			assert.False(t, checkIfReady(pod), "Name not available still returning Pod to be ready")
		})

		t.Run("Namespace not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Namespace = ""
			assert.False(t, checkIfReady(pod), "Namespace not available still returning Pod to be ready")
		})

		t.Run("Pod IP not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Status.PodIP = ""
			assert.False(t, checkIfReady(pod), "Pod IP not available still returning Pod to be ready")
		})

		t.Run("Pod APIVersion not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.APIVersion = ""
			assert.False(t, checkIfReady(pod), "Pod APIVersion not available still returning Pod to be ready")
		})

		t.Run("Pod Kind is not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Kind = ""
			assert.False(t, checkIfReady(pod), "Pod Kind not available still returning Pod to be ready")
		})

		t.Run("Pod IPs not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Status.PodIPs = nil
			assert.False(t, checkIfReady(pod), "Pod IPs not available still returning Pod to be ready")
		})

		t.Run("Pod labels not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Labels = nil
			assert.False(t, checkIfReady(pod), "Pod Labels not available still returning Pod to be ready")
		})

		t.Run("Pod annotations not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Annotations = nil
			assert.False(t, checkIfReady(pod), "Pod Annotations not available still returning Pod to be ready")
		})

		t.Run("Pod UID not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.UID = ""
			assert.False(t, checkIfReady(pod), "Pod UID not available still returning Pod to be ready")
		})
	})
}

func TestCheckIfChanged(t *testing.T) {
	t.Run("Check if the pod and podInfo are different", func(t *testing.T) {

		// All fields match
		t.Run("All fields same", func(*testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			assert.False(t, checkIfChanged(pod, podInfo), "All fields match, still returning pod to be changed")
		})

		// Fields mismatch
		t.Run("Name not available", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			pod.Name = getRandString(getRandNum())

			assert.True(t, checkIfChanged(pod, podInfo), "Pod Name changed, still returning pod not changed")
		})

		t.Run("Namespace of the pod changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			pod.Namespace = getRandString(getRandNum())

			assert.True(t, checkIfChanged(pod, podInfo), "Pod Namespace changed, still returning pod not changed")
		})

		t.Run("Pod IP of the pod changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			pod.Status.PodIP = getRandIP()
			assert.True(t, checkIfChanged(pod, podInfo), "Pod IP changed, still returning pod not changed")
		})

		t.Run("Pod IPs changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			randIP, randIPs := getRandIPs()

			randPodIPs := make([]corev1.PodIP, len(randIPs))
			for i, IP := range randIPs {
				randPodIPs[i] = corev1.PodIP{IP: IP}
			}
			pod.Status.PodIP = randIP
			pod.Status.PodIPs = randPodIPs

			assert.True(t, checkIfChanged(pod, podInfo), "Pod IPs changed, still returning pod not changed")
		})

		t.Run("Pod Labels changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			pod.Labels = getRandMap()
			assert.True(t, checkIfChanged(pod, podInfo), "Pod Labels changed, still returning pod not changed")
		})

		t.Run("Pod annotations changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			pod.Annotations = getRandMap()
			assert.True(t, checkIfChanged(pod, podInfo), "Pod Annotations changed, still returning pod not changed")
		})

		t.Run("Pod UID Changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)
			pod.UID = uuid.NewUUID()
			assert.True(t, checkIfChanged(pod, podInfo), "Pod UID changed, still returning pod not changed")
		})
	})
}

func TestOwnerReferenceChanged(t *testing.T) {
	t.Run("Check if owner reference changed", func(t *testing.T) {

		t.Run("Owner reference not changed", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)

			assert.False(t, ownerReferenceChanged(pod, podInfo), "Owner Reference match, still returning false")
		})

		t.Run("Owner Name mismatch", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)

			podInfo.OwnerReferences[0].Name = getRandString(getRandNum())
			assert.True(t, ownerReferenceChanged(pod, podInfo), "Owner name mismatch, owner Name : %s Pod Name: %s. Still returning ownerReference not changed", podInfo.OwnerReferences[0].Name, pod.Name)
		})

		t.Run("Owner UID mismatch", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)

			podInfo.OwnerReferences[0].UID = uuid.NewUUID()
			assert.True(t, ownerReferenceChanged(pod, podInfo), "Owner UID mismatch, owner UID : %s Pod UID: %s. Still returning ownerReference not changed", podInfo.OwnerReferences[0].UID, pod.UID)
		})
		t.Run("Owner Kind mismatch", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)

			podInfo.OwnerReferences[0].Kind = getRandString(getRandNum())
			assert.True(t, ownerReferenceChanged(pod, podInfo), "Owner Kind mismatch, owner Kind : %s Pod Kind: %s. Still returning ownerReference not changed", podInfo.OwnerReferences[0].Kind, pod.Kind)
		})

		t.Run("API Version mismatch", func(t *testing.T) {
			pod := randomPodGenerator()
			podInfo := getPodInfo(pod)

			podInfo.OwnerReferences[0].APIVersion = getRandString(getRandNum())
			assert.True(t, ownerReferenceChanged(pod, podInfo), "Owner Kind mismatch, owner APIVersion : %s Pod APIVersion: %s. Still returning ownerReference not changed", podInfo.OwnerReferences[0].APIVersion, pod.APIVersion)
		})
	})
}
