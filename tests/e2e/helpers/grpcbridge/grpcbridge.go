// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package grpcbridge deploys a lightweight DaemonSet that bridges the Tetragon
// gRPC Unix socket to a TCP port so that e2e tests can reach it via a standard
// kubectl port-forward.
package grpcbridge

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	// DaemonSetName is the name given to the bridge DaemonSet.
	DaemonSetName = "tetragon-grpc-bridge"

	// SocatPort is the TCP port that socat listens on inside each bridge pod.
	SocatPort = 54321
)

// Deploy creates the gRPC bridge DaemonSet in the given namespace, waits for all
// pods to become ready, and registers a Finish hook that deletes the DaemonSet
// when the test environment tears down.
func Deploy(ctx context.Context, r *resources.Resources, testenv env.Environment, namespace string) error {
	ds := buildDaemonSet(namespace)
	klog.InfoS("Deploying gRPC bridge DaemonSet", "namespace", namespace)

	if err := r.Create(ctx, ds); err != nil {
		return fmt.Errorf("failed to create gRPC bridge DaemonSet: %w", err)
	}

	klog.Info("Waiting for gRPC bridge DaemonSet to be ready...")
	if err := wait.For(
		conditions.New(r).ResourceMatch(ds, func(object k8s.Object) bool {
			o := object.(*appsv1.DaemonSet)
			return o.Status.NumberReady == o.Status.DesiredNumberScheduled &&
				o.Status.DesiredNumberScheduled > 0
		}),
		wait.WithTimeout(3*time.Minute),
		wait.WithInterval(5*time.Second),
	); err != nil {
		return fmt.Errorf("gRPC bridge DaemonSet did not become ready: %w", err)
	}
	klog.Info("gRPC bridge DaemonSet is ready!")

	testenv.Finish(func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		klog.InfoS("Deleting gRPC bridge DaemonSet", "namespace", namespace)
		if err := r.Delete(ctx, buildDaemonSet(namespace)); err != nil {
			klog.ErrorS(err, "Failed to delete gRPC bridge DaemonSet")
		}
		return ctx, nil
	})

	return nil
}

func buildDaemonSet(namespace string) *appsv1.DaemonSet {
	labels := map[string]string{"app.kubernetes.io/name": DaemonSetName}
	hostPathType := corev1.HostPathDirectoryOrCreate

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DaemonSetName,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "socat",
						Image: "docker.io/library/alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11",
						Command: []string{
							"sh", "-c",
							"apk add --no-cache -q socat && " +
								"exec socat TCP-LISTEN:54321,reuseaddr,fork " +
								"UNIX-CLIENT:/var/run/tetragon/tetragon.sock",
						},
						Ports: []corev1.ContainerPort{{
							ContainerPort: SocatPort,
							Protocol:      corev1.ProtocolTCP,
						}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								TCPSocket: &corev1.TCPSocketAction{
									Port: intstr.FromInt32(SocatPort),
								},
							},
							PeriodSeconds:    5,
							FailureThreshold: 30,
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "tetragon-run",
							MountPath: "/var/run/tetragon",
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "tetragon-run",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/run/tetragon",
								Type: &hostPathType,
							},
						},
					}},
				},
			},
		},
	}
}
