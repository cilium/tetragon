// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"

	"github.com/stretchr/testify/require"
)

func miniTcpNopServer(c chan<- bool) {
	miniTcpNopServerWithPort(c, 9919, false)
}

func miniTcpNopServer6(c chan<- bool) {
	miniTcpNopServerWithPort(c, 9919, true)
}

func miniTcpNopServerWithPort(c chan<- bool, port int, ipv6 bool) {
	var conn net.Listener
	var err error
	if !ipv6 {
		conn, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	} else {
		conn, err = net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
	}
	if err != nil {
		panic(err)
	}
	c <- true
	ses, _ := conn.Accept()
	ses.Close()
	conn.Close()
}

func TestKprobeSockBasic(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "DPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "9919"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockNotPort(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "NotDPort"
        values:
        - "9918"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDPort"
        values:
        - "9918"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockMultiplePorts(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "DPort"
        values:
        - "9910"
        - "9919"
        - "9925"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "9910"
        - "9919"
        - "9925"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockPortRange(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "DPort"
        values:
        - "9910:9920"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "9910:9920"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockPrivPorts(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "DPortPriv"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPortPriv"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServerWithPort(tcpReady, 1020, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:1020")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(1020),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockNotPrivPorts(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "NotDPortPriv"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDPortPriv"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockNotCIDR(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
      - index: 0
        operator: "DPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockNotCIDRWrongAF(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "::"
      - index: 0
        operator: "DPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "::"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockMultipleCIDRs(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "10.0.0.1"
        - "127.0.0.1"
        - "172.16.0.0/16"
      - index: 0
        operator: "DPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "10.0.0.1"
        - "127.0.0.1"
        - "172.16.0.0/16"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockState(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-set-state"
spec:
  kprobes:
  - call: "tcp_set_state"
    syscall: false
    args:
    - index: 0
      type: "sock"
    - index: 1
      type: "int"
      label: "state"
    selectors:
    - matchArgs:
      - index: 0
        operator: "SAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "SPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
      - index: 0
        operator: "State"
        values:
        - "TCP_SYN_RECV"
      - index: 1
        operator: "Equal"
        values:
        - 1
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-set-state"
spec:
  kprobes:
  - call: "tcp_set_state"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "State"
        values:
        - "TCP_SYN_RECV"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-state-checker").
		WithFunctionName(sm.Full("tcp_set_state")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithSaddr(sm.Full("127.0.0.1")).
					WithSport(9919).
					WithState(sm.Full("TCP_SYN_RECV")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockFamily(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 0
        operator: "DPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
      - index: 0
        operator: "Family"
        values:
        - "AF_INET"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Family"
        values:
        - "AF_INET"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9919).
					WithFamily(sm.Full("AF_INET")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSocketAndSockaddr(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "security-socket-connect"
spec:
  kprobes:
  - call: "security_socket_connect"
    syscall: false
    args:
    - index: 0
      type: "socket"
    - index: 1
      type: "sockaddr"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
      - index: 1
        operator: "SAddr"
        values:
        - "127.0.0.1"
      - index: 1
        operator: "SPort"
        values:
        - "9919"
      - index: 1
        operator: "Family"
        values:
        - "AF_INET"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "security-socket-connect"
spec:
  kprobes:
  - call: "security_socket_connect"
    syscall: false
    args:
    - index: 0
      type: "socket"
    - index: 1
      type: "sockaddr"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("security-socket-connect-checker").
		WithFunctionName(sm.Full("security_socket_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockaddrArg(ec.NewKprobeSockaddrChecker().
					WithAddr(sm.Full("127.0.0.1")).
					WithPort(9919).
					WithFamily(sm.Full("AF_INET"))),
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithProtocol(sm.Full("IPPROTO_TCP")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSkb(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "datagram"
spec:
  kprobes:
  - call: "ip_send_skb"
    syscall: false
    args:
    - index: 1
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 1
        operator: "DAddr"
        values:
        - "127.0.0.1"
      - index: 1
        operator: "DPort"
        values:
        - "53"
      - index: 1
        operator: "Protocol"
        values:
        - "IPPROTO_UDP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "datagram"
spec:
  kprobes:
  - call: "ip_send_skb"
    syscall: false
    args:
    - index: 1
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 1
        operator: "DPort"
        values:
        - "53"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			dial := net.Dialer{}
			return dial.Dial("udp", "127.0.0.1:53")
		},
	}
	res.LookupIP(context.Background(), "ip4", "ebpf.io")

	kpChecker := ec.NewProcessKprobeChecker("datagram-checker").
		WithFunctionName(sm.Full("ip_send_skb")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLabel(sm.Full("datagram")).
					WithSkbArg(ec.NewKprobeSkbChecker().
						WithDaddr(sm.Full("127.0.0.1")).
						WithDport(53).
						WithProtocol(sm.Full("IPPROTO_UDP")),
					),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSockIpv6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "::1"
      - index: 0
        operator: "DPort"
        values:
        - "9919"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "::1"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tcpReady := make(chan bool)
	go miniTcpNopServer6(tcpReady)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "[::1]:9919")
	require.NoError(t, err)
	_, err = net.DialTCP("tcp", nil, addr)
	require.NoError(t, err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("::1")).
					WithDport(9919),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeSkbIpv6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	hookFull := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "datagram"
spec:
  kprobes:
  - call: "ip6_send_skb"
    syscall: false
    args:
    - index: 0
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "::1"
      - index: 0
        operator: "DPort"
        values:
        - "53"
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_UDP"
`
	hookPart := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "datagram"
spec:
  kprobes:
  - call: "ip6_send_skb"
    syscall: false
    args:
    - index: 0
      type: "skb"
      label: "datagram"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "::1"
`

	if config.EnableLargeProgs() {
		createCrdFile(t, hookFull)
	} else {
		createCrdFile(t, hookPart)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			dial := net.Dialer{}
			return dial.Dial("udp", "[::1]:53")
		},
	}
	res.LookupIP(context.Background(), "ip4", "ebpf.io")

	kpChecker := ec.NewProcessKprobeChecker("datagram-checker").
		WithFunctionName(sm.Full("ip6_send_skb")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLabel(sm.Full("datagram")).
					WithSkbArg(ec.NewKprobeSkbChecker().
						WithDaddr(sm.Full("::1")).
						WithDport(53).
						WithProtocol(sm.Full("IPPROTO_UDP")),
					),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}
