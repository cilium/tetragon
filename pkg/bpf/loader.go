// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

func QdiscTCInsert(linkName string, ingress bool) error {
	return nil
}

func AttachTCIngress(progFd int, linkName string, ingress bool) error {
	return nil
}
