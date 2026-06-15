// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	// runLabelKey is the pod label whose unique per-run value scopes the
	// generated policy to the test pod (it is passed as the podSelector).
	runLabelKey = "tetragon.io/policytest-run"

	// containerName is the name of the test pod's single container.
	containerName = "policytest"

	// tlsVolumeName / tlsMountPath are the in-pod location of the mounted gRPC
	// client TLS credentials (ca.crt, tls.crt, tls.key).
	tlsVolumeName = "tetragon-tls"
	tlsMountPath  = "/var/run/tetragon-tls"

	// DefaultImage is the policytest image built by `make image-policytest`.
	// Override via the orchestrator's --image flag.
	DefaultImage = "cilium/tetragon-policytest:latest"
)

// TestPodSpec describes the inputs needed to build a test pod that runs policy
// tests from within the cluster.
type TestPodSpec struct {
	// Name of the test pod.
	Name string
	// Namespace of the test pod and the namespaced policy it loads.
	Namespace string
	// Node to pin the pod to (co-located with the target Tetragon agent).
	Node string
	// Image is the policytest image (tetra + tester-progs).
	Image string
	// RunID is a unique value for this run; it becomes the run label value that
	// the policy's podSelector matches.
	RunID string
	// AgentAddr is the node-local Tetragon agent gRPC address.
	AgentAddr string
	// Tests is the set of registered policy test names to run.
	Tests []string
	// TLSSecret, when set, is the name of a kubernetes.io/tls secret (ca.crt,
	// tls.crt, tls.key) in the test pod's namespace, mounted and used as the
	// gRPC client's mTLS credentials. Empty means a plaintext connection.
	TLSSecret string
	// TLSServerName overrides the SNI / certificate hostname when dialing,
	// needed when connecting by an IP that is not in the agent cert's SANs.
	TLSServerName string
}

// Build returns the Pod that runs `tetra policytest run-inpod` for the
// configured tests, scoped to this pod via the run label.
func (s *TestPodSpec) Build() *corev1.Pod {
	labels := map[string]string{runLabelKey: s.RunID}

	var args []string
	if s.AgentAddr != "" {
		args = append(args, "--server-address", s.AgentAddr)
	}

	var volumes []corev1.Volume
	var mounts []corev1.VolumeMount
	if s.TLSSecret != "" {
		volumes = append(volumes, corev1.Volume{
			Name: tlsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: s.TLSSecret},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      tlsVolumeName,
			MountPath: tlsMountPath,
			ReadOnly:  true,
		})
		args = append(args,
			"--tls-ca-cert-files", tlsMountPath+"/ca.crt",
			"--tls-cert-file", tlsMountPath+"/tls.crt",
			"--tls-key-file", tlsMountPath+"/tls.key",
		)
		if s.TLSServerName != "" {
			args = append(args, "--tls-server-name", s.TLSServerName)
		}
	}

	args = append(args, "policytest", "run-inpod")
	args = append(args, s.Tests...)
	args = append(args, "--namespace", s.Namespace)
	args = append(args, "--pod-selector-label", runLabelKey+"="+s.RunID)

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.Name,
			Namespace: s.Namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			NodeName:      s.Node,
			// The test pod talks only to the agent over gRPC, never the
			// Kubernetes API, so it needs no service account token.
			AutomountServiceAccountToken: ptr.To(false),
			Volumes:                      volumes,
			Containers: []corev1.Container{{
				Name:            containerName,
				Image:           s.Image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Args:            args,
				VolumeMounts:    mounts,
				// Trigger programs assume the root capabilities the local
				// runner has under sudo (e.g. null-mount calls mount()).
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
			}},
		},
	}
}
