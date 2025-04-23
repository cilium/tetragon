// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package gops is a simple gops client implementation to dump gops info from end-to-end
// tests.
package gops

import (
	"fmt"
	"io"
	"net"

	"github.com/google/gops/signal"
)

func DumpHeapProfile(addr net.TCPAddr) ([]byte, error) {
	out, err := cmd(addr, signal.HeapProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to dump heap profile: %w", err)
	}
	return out, nil
}

func DumpMemStats(addr net.TCPAddr) ([]byte, error) {
	out, err := cmd(addr, signal.MemStats)
	if err != nil {
		return nil, fmt.Errorf("failed to dump memstats: %w", err)
	}
	return out, nil
}

func cmd(addr net.TCPAddr, sig byte) ([]byte, error) {
	conn, err := net.DialTCP("tcp", nil, &addr)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte{sig}); err != nil {
		return nil, err
	}

	out, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}

	return out, nil
}
