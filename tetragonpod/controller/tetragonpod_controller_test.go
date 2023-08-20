package controller

import (
	"crypto/rand"
	"fmt"
	ciliumiov1alpha1 "github.com/cilium/tetragon/tetragonpod/api/v1alpha1"
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

// printPod prints the pod
func printPod(pod *corev1.Pod) {
	fmt.Printf("Pod:\n")
	fmt.Printf("  Kind: %s\n", pod.Kind)
	fmt.Printf("  API Version: %s\n", pod.APIVersion)
	fmt.Printf("  Metadata:\n")
	fmt.Printf("    Name: %s\n", pod.Name)
	fmt.Printf("    Namespace: %s\n", pod.Namespace)
	fmt.Printf("    UID: %s\n", pod.UID)
	fmt.Printf("    Labels: %v\n", pod.Labels)
	fmt.Printf("    Annotations: %v\n", pod.Annotations)
	fmt.Printf("  Status:\n")
	fmt.Printf("    Pod IP: %s\n", pod.Status.PodIP)
	fmt.Printf("    Pod IPs:\n")
	for _, ip := range pod.Status.PodIPs {
		fmt.Printf("      IP: %s\n", ip.IP)
	}
}

func printPodInfo(podInfo *ciliumiov1alpha1.TetragonPod) {
	fmt.Println("Pod Information:")
	fmt.Printf("  Name: %s\n", podInfo.Name)
	fmt.Printf("  Namespace: %s\n", podInfo.Namespace)
	fmt.Printf("  Labels: %v\n", podInfo.Labels)
	fmt.Printf("  Annotations: %v\n", podInfo.Annotations)

	fmt.Println("Owner References:")
	for _, ownerRef := range podInfo.OwnerReferences {
		fmt.Printf("  API Version: %s\n", ownerRef.APIVersion)
		fmt.Printf("  Kind: %s\n", ownerRef.Kind)
		fmt.Printf("  Name: %s\n", ownerRef.Name)
		fmt.Printf("  UID: %s\n", ownerRef.UID)
	}

	fmt.Println("Status:")
	fmt.Printf("  Pod IP: %s\n", podInfo.Status.PodIP)
	fmt.Println("  Pod IPs:")
	for _, ip := range podInfo.Status.PodIPs {
		fmt.Printf("    IP: %s\n", ip.IP)
	}
}

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

//func getRandIP() string {
//	randIP := fmt.Sprintf("10.%d.%d.%d", getRandNum(), getRandNum(), getRandNum())
//	fmt.Println(randIP)
//	return randIP
//}
//
//func getRandIPs() (string, []string) {
//	podIPs := []string{getRandIP()}
//	length := getRandNum() + 1
//	for i := 1; i <= length; i++ {
//		podIPs[i] = getRandIP()
//	}
//	return podIPs[0], podIPs
//}

func randomPodGenerator() *corev1.Pod {
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
			PodIP:  "10.1.1.1",
			PodIPs: []corev1.PodIP{{IP: "10.1.1.1"}},
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
		expectedPod := getPodInfo(pod)
		generatedPod := generatePod(pod)

		if !reflect.DeepEqual(expectedPod, generatedPod) {
			t.Errorf("Generated Pods are not equal \nExpected: %+v\nGot: %+v", pod, generatedPod)
		}
	})
}

func TestCheckIfReady(t *testing.T) {
	t.Run("Check if all the necessary fields of pod are available", func(t *testing.T) {

		var expected bool
		var got bool

		// test ready pod.
		t.Run("All fields available", func(*testing.T) {
			pod := randomPodGenerator()
			got = checkIfReady(pod)
			expected = true
			if got != expected {
				t.Errorf("Returned pod to be not ready even if it was. Expected %t Got %t", expected, got)
			}
		})

		// test non-ready pods.
		t.Run("Name not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Name = ""
			expected = false
			got = checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Namespace not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Namespace = ""
			expected = false
			got := checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Pod IP not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Status.PodIP = ""
			expected = false
			got := checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Pod APIVersion not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.APIVersion = ""
			expected = false
			got := checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Pod Kind is not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Kind = ""
			expected = false
			got := checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Pod IPs not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Status.PodIPs = nil
			expected = false
			got := checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Pod labels not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Labels = nil
			expected = false
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Pod annotations not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.Annotations = nil
			expected = false
			got := checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})

		t.Run("Pod UID not available", func(t *testing.T) {
			pod := randomPodGenerator()
			pod.UID = ""
			expected = false
			got := checkIfReady(pod)
			if got != expected {
				t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
			}
		})
	})
}

func TestOwnerReferenceChanged(t *testing.T) {
	t.Run("Check if owner reference changed", func(t *testing.T) {
		pod := randomPodGenerator()
		podInfo := getPodInfo(pod)
		got := ownerReferenceChanged(pod, podInfo)
		expected := false
		if got != expected {
			t.Errorf("Returned pod to be ready even if it was not. Expected %t Got %t", expected, got)
		}
	})
}
