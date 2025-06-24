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
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"

	"github.com/stretchr/testify/suite"
)

func miniTCPNopServerWithPort(c chan<- bool, port int, ipv6 bool) {
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

func (suite *KprobeNet) addTracingPolicy(tpYaml string) tracingpolicy.TracingPolicy {
	tp, err := tracingpolicy.FromYAML(tpYaml)
	suite.Require().NoError(err)
	err = observer.GetSensorManager().AddTracingPolicy(suite.ctx, tp)
	suite.Require().NoError(err)
	return tp
}

func (suite *KprobeNet) deleteTracingPolicy(tp tracingpolicy.TracingPolicy) {
	err := observer.GetSensorManager().DeleteTracingPolicy(suite.ctx, tp.TpName(), "")
	suite.Require().NoError(err)
}

type KprobeNet struct {
	suite.Suite
	doneWG, readyWG sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
}

func TestKprobeNet(t *testing.T) {
	suite.Run(t, new(KprobeNet))
}

func (suite *KprobeNet) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	obs, err := observertesthelper.GetDefaultObserver(suite.T(), suite.ctx, tus.Conf().TetragonLib)
	suite.Require().NoError(err)
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *KprobeNet) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		testutils.DoneWithExportFile(suite.T())
	}
}

func (suite *KprobeNet) TearDownSuite() {
	suite.cancel()
	suite.doneWG.Wait()
}

func (suite *KprobeNet) TestKprobeSockBasic() {
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9919, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9919")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

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

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockNotPort() {
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9920, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9920")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9920),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockMultiplePorts() {
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
        - "9921"
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
        - "9921"
        - "9925"
`

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9921, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9921")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9921),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockPortRange() {
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
        - "9922:9932"
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
        - "9922:9932"
`

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9922, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9922")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9922),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockPrivPorts() {
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 1020, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:1020")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

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

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockNotPrivPorts() {
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9933, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9933")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9933),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockNotCIDR() {
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
        - "9934"
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9934, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9934")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9934),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockNotCIDRWrongAF() {
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
        - "9935"
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9935, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9935")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9935),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockMultipleCIDRs() {
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
        - "9936"
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9936, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9936")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9936),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockState() {
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
        - "9937"
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9937, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9937")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-state-checker").
		WithFunctionName(sm.Full("tcp_set_state")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithSaddr(sm.Full("127.0.0.1")).
					WithSport(9937).
					WithState(sm.Full("TCP_SYN_RECV")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockFamily() {
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
        - "9938"
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9938, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9938")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("127.0.0.1")).
					WithDport(9938).
					WithFamily(sm.Full("AF_INET")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSocketAndSockaddr() {
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
        - "9939"
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9939, false)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9939")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("security-socket-connect-checker").
		WithFunctionName(sm.Full("security_socket_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockaddrArg(ec.NewKprobeSockaddrChecker().
					WithAddr(sm.Full("127.0.0.1")).
					WithPort(9939).
					WithFamily(sm.Full("AF_INET"))),
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithProtocol(sm.Full("IPPROTO_TCP")),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSkb() {
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

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

	err := jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSockIpv6() {
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
        - "9940"
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	tcpReady := make(chan bool)
	go miniTCPNopServerWithPort(tcpReady, 9940, true)
	<-tcpReady
	addr, err := net.ResolveTCPAddr("tcp", "[::1]:9940")
	suite.Require().NoError(err)
	_, err = net.DialTCP("tcp", nil, addr)
	suite.Require().NoError(err)

	kpChecker := ec.NewProcessKprobeChecker("tcp-connect-checker").
		WithFunctionName(sm.Full("tcp_connect")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(ec.NewKprobeSockChecker().
					WithDaddr(sm.Full("::1")).
					WithDport(9940),
				),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeSkbIpv6() {
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

	hook := hookFull
	if !config.EnableLargeProgs() {
		hook = hookPart
	}

	suite.readyWG.Wait()

	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

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

	err := jsonchecker.JSONTestCheckExpectWithKeep(suite.T(), checker, false, false)
	suite.Require().NoError(err)
}
