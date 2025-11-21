// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package process

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/watcher"
)

var (
	k8s any
)

func getPodInfo(
	w any,
	containerID string,
	binary string,
	args string,
	nspid uint32,
) *tetragon.Pod {
	return nil
}
func GetK8s() watcher.PodAccessor {
	return nil
}
