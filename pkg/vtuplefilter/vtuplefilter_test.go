// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package vtuplefilter

import (
	"testing"

	"github.com/isovalent/tetragon-oss/pkg/vtuple"
)

type VTRes struct {
	vt  vtuple.Impl
	res bool
}

type LineTestCase struct {
	line  string
	tests []VTRes
}

var (
	ip10 = [4]byte{10, 1, 1, 10}
	ip20 = [4]byte{10, 1, 1, 20}

	LineTestCases = []LineTestCase{
		{
			line: "sport=9999",
			tests: []VTRes{
				{vt: vtuple.CreateTCPv4(ip10, 9999, ip20, 4242), res: true},
				{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 9999), res: false},
				{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 1234), res: false},
			},
		},
		{
			line: "dport=9999",
			tests: []VTRes{
				{vt: vtuple.CreateTCPv4(ip10, 9999, ip20, 4242), res: false},
				{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 9999), res: true},
				{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 1234), res: false},
			},
		},
		{
			line: "port=9999",
			tests: []VTRes{
				{vt: vtuple.CreateTCPv4(ip10, 9999, ip20, 4242), res: true},
				{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 9999), res: true},
				{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 1234), res: false},
			},
		},

		// TODO: more tests
	}
)

func doLineTest(t *testing.T, c *LineTestCase) {
	filter, err := FromLine(c.line)
	if err != nil {
		t.Errorf("failed to parse line %s: %s", c.line, err)
	}

	for _, vtres := range c.tests {
		res := filter.FilterFn(&vtres.vt)
		if res != vtres.res {
			t.Errorf("filter:%s tuple:%s expected_result:%t result:%t", c.line, vtuple.StringRep(&vtres.vt), vtres.res, res)
		}

	}
}

func TestLines(t *testing.T) {
	for _, tc := range LineTestCases {
		doLineTest(t, &tc)
	}
}
