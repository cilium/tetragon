// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package cgidmap

import "github.com/cilium/tetragon/pkg/api/processapi"

func SetContainerID(info *processapi.MsgK8sUnix) {
	return
}
