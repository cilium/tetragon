// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"net"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
)

func dnsRawQuery() []byte {
	hdr := []byte{0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	q := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
	tail := []byte{0, 1, 0, 1}
	return append(append(hdr, q...), tail...)
}

func (suite *KprobeNet) TestKprobeDnsExample() {
	if !config.EnableLargeProgs() {
		suite.T().Skip("DNS parser requires __LARGE_BPF_PROG")
	}

	hook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp-dns-egress"
spec:
  kprobes:
  - call: "udp_sendmsg"
    syscall: false
    args:
    - index: 0
      type: "sock"
    - index: 1
      type: "dns"
      label: "dns"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "53"
      - index: 1
        operator: "Postfix"
        values:
        - "example.test"
`

	suite.readyWG.Wait()
	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	conn, err := net.Dial("udp4", "127.0.0.1:53")
	suite.Require().NoError(err)
	defer conn.Close()
	_, err = conn.Write(dnsRawQuery())
	suite.Require().NoError(err)

	kp := ec.NewProcessKprobeChecker("udp-dns-egress").
		WithFunctionName(sm.Full("udp_sendmsg")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithSockArg(
					ec.NewKprobeSockChecker().WithDport(53),
				),
				ec.NewKprobeArgumentChecker().WithDnsArg(
					ec.NewKprobeDnsChecker().
						WithQueryName(sm.Full("example.test")).
						WithQueryTypeStr(sm.Full("A")).
						WithParsed(true).
						WithResponse(false),
				).WithLabel(sm.Full("dns")),
			))

	err = jsonchecker.JsonTestCheckExpectWithKeep(suite.T(), ec.NewUnorderedEventChecker(kp), false, false)
	suite.Require().NoError(err)
}

func (suite *KprobeNet) TestKprobeDnsPostfixNoMatch() {
	if !config.EnableLargeProgs() {
		suite.T().Skip("DNS parser requires __LARGE_BPF_PROG")
	}

	hook := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp-dns-egress-strict"
spec:
  kprobes:
  - call: "udp_sendmsg"
    syscall: false
    args:
    - index: 0
      type: "sock"
    - index: 1
      type: "dns"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "53"
      - index: 1
        operator: "Postfix"
        values:
        - "example.test"
`

	suite.readyWG.Wait()
	tp := suite.addTracingPolicy(hook)
	defer suite.deleteTracingPolicy(tp)

	pkt := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	pkt = append(pkt, 5, 'o', 't', 'h', 'e', 'r', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0)
	pkt = append(pkt, 0, 1, 0, 1)

	conn, err := net.Dial("udp4", "127.0.0.1:53")
	suite.Require().NoError(err)
	defer conn.Close()
	_, err = conn.Write(pkt)
	suite.Require().NoError(err)

	err = jsonchecker.JsonTestCheckExpectWithKeep(suite.T(), ec.NewUnorderedEventChecker(), false, false)
	suite.Require().NoError(err)
}
