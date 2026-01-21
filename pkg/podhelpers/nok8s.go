// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package podhelpers

type ContainerInfo struct {
	Name string
	Repo string
}

func PodContainersIDs(pod any) []string {
	return nil
}

func PodContainersInfo(pod any) []ContainerInfo {
	return nil
}

type DummyWorkload struct {
	Name string
}

type DummyType struct {
	Kind string
}

func GetWorkloadMetaFromPod(pod any) (DummyWorkload, DummyType) {
	return DummyWorkload{}, DummyType{}
}
