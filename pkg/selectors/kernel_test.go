// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// go test -gcflags="" -c ./pkg/selectors -o go-tests/selectors.test
// sudo ./go-tests/selectors.test  [ -test.run TestCopyFileRange ]

package selectors

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/config"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/idtable"
)

func TestWriteSelectorUint32(t *testing.T) {
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	v := uint32(0x1234abcd)

	WriteSelectorUint32(d, v)
	if d.e[3] != 0x12 || d.e[2] != 0x34 || d.e[1] != 0xab || d.e[0] != 0xcd {
		t.Errorf("SelectorStateWrite failed: %x %x %x %x\n",
			d.e[0], d.e[1], d.e[2], d.e[3])
	}

	d.off = 1024
	WriteSelectorUint32(d, v)
	if d.e[1027] != 0x12 || d.e[1026] != 0x34 || d.e[1025] != 0xab || d.e[1024] != 0xcd {
		t.Errorf("SelectorStateWrite offset(1024) failed: %x %x %x %x\n",
			d.e[1027], d.e[1026], d.e[1025], d.e[1024])
	}
}

func TestWriteSelectorLength(t *testing.T) {
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	v := uint32(0x1234abcd)

	e1 := 8
	e2 := 12

	off := AdvanceSelectorLength(d)
	WriteSelectorUint32(d, v)
	WriteSelectorLength(d, off)

	off = AdvanceSelectorLength(d)
	WriteSelectorUint32(d, v)
	WriteSelectorUint32(d, v)
	WriteSelectorLength(d, off)

	// Length fields include the length value
	if d.e[3] != 0 || d.e[2] != 0 || d.e[1] != 0 || d.e[0] != 8 {
		t.Errorf("WriteSelectorLength(0): expected %d actual 0X%x%x%x%x\n", e1, d.e[0], d.e[1], d.e[2], d.e[3])
	}
	if d.e[11] != 0 || d.e[10] != 0 || d.e[9] != 0 || d.e[8] != 12 {
		t.Errorf("WriteSelectorLength(8): expected %d actual 0X%x%x%x%x\n", e2, d.e[8], d.e[9], d.e[10], d.e[11])
	}
}

func TestWriteSelectorByteArray(t *testing.T) {
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	v := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

	off1 := AdvanceSelectorLength(d)
	off2 := AdvanceSelectorLength(d)
	WriteSelectorByteArray(d, v, uint32(len(v)))
	WriteSelectorLength(d, off2)
	WriteSelectorLength(d, off1)

	// Length fields include the length value
	if d.e[3] != 0 || d.e[2] != 0 || d.e[1] != 0 || d.e[0] != 23 {
		t.Errorf("WriteSelectorLength(0): expected 0X%x actual 0X%x%x%x%x\n", 23, d.e[0], d.e[1], d.e[2], d.e[3])
	}
	if d.e[7] != 0 || d.e[6] != 0 || d.e[5] != 0 || d.e[4] != 19 {
		t.Errorf("WriteSelectorLength(8): expected 0X%x actual 0X%x%x%x%x\n", 19, d.e[4], d.e[5], d.e[6], d.e[7])
	}
	// Byte array
	if d.e[8] != 1 || d.e[9] != 2 || d.e[10] != 3 || d.e[11] != 4 ||
		d.e[12] != 5 || d.e[13] != 6 || d.e[14] != 7 || d.e[15] != 8 ||
		d.e[16] != 9 || d.e[17] != 0xa || d.e[18] != 0xb || d.e[19] != 0xc ||
		d.e[20] != 0xd || d.e[21] != 0xe || d.e[22] != 0xf {
		t.Errorf("WriteSelectorLength(8): expected %x actual 0X%x\n", v, d.e[8:])
	}

}

func TestArgSelectorValue(t *testing.T) {
	astring := &v1alpha1.ArgSelector{Index: 1, Operator: "Equal", Values: []string{"foobar"}}

	b, l := ArgSelectorValue(astring.Values[0])
	if bytes.Equal(b, []byte("foobar")) == false || l != 6 {
		t.Errorf("argSelectorValue: expected %v %v actual %v %v\n", []byte("foobar"), 6, b, l)
	}
}

func TestSelectorOp(t *testing.T) {
	if op, err := SelectorOp("gt"); op != SelectorOpGT || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpGT, op, err)
	}
	if op, err := SelectorOp("lt"); op != SelectorOpLT || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpLT, op, err)
	}
	if op, err := SelectorOp("eq"); op != SelectorOpEQ || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpEQ, op, err)
	}
	if op, err := SelectorOp("Equal"); op != SelectorOpEQ || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpEQ, op, err)
	}
	if op, err := SelectorOp("neq"); op != SelectorOpNEQ || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNEQ, op, err)
	}
	if op, err := SelectorOp("Mask"); op != SelectorOpMASK || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpMASK, op, err)
	}
	if op, err := SelectorOp("In"); op != SelectorOpIn || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpIn, op, err)
	}
	if op, err := SelectorOp("NotIn"); op != SelectorOpNotIn || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNotIn, op, err)
	}
	if op, err := SelectorOp("SPort"); op != SelectorOpSport || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpSport, op, err)
	}
	if op, err := SelectorOp("DPort"); op != SelectorOpDport || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpDport, op, err)
	}
	if op, err := SelectorOp("NotSPort"); op != SelectorOpNotSport || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNotSport, op, err)
	}
	if op, err := SelectorOp("NotDPort"); op != SelectorOpNotDport || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNotDport, op, err)
	}
	if op, err := SelectorOp("SPortPriv"); op != SelectorOpSportPriv || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpSportPriv, op, err)
	}
	if op, err := SelectorOp("DPortPriv"); op != SelectorOpDportPriv || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpDportPriv, op, err)
	}
	if op, err := SelectorOp("NotSPortPriv"); op != SelectorOpNotSportPriv || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNotSportPriv, op, err)
	}
	if op, err := SelectorOp("NotDPortPriv"); op != SelectorOpNotDportPriv || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNotDportPriv, op, err)
	}
	if op, err := SelectorOp("foo"); op != 0 || err == nil {
		t.Errorf("selectorOp: expected error actual %d %v\n", op, err)
	}
	if op, err := SelectorOp("SAddr"); op != SelectorOpSaddr || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpSaddr, op, err)
	}
	if op, err := SelectorOp("DAddr"); op != SelectorOpDaddr || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpDaddr, op, err)
	}
	if op, err := SelectorOp("NotSAddr"); op != SelectorOpNotSaddr || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNotSaddr, op, err)
	}
	if op, err := SelectorOp("NotDAddr"); op != SelectorOpNotDaddr || err != nil {
		t.Errorf("selectorOp: expected %d actual %d %v\n", SelectorOpNotDaddr, op, err)
	}
}

func TestPidSelectorFlags(t *testing.T) {
	pid := &v1alpha1.PIDSelector{Operator: "In", Values: []uint32{1, 2, 3}, IsNamespacePID: true, FollowForks: true}
	if flags := pidSelectorFlags(pid); flags != 0x3 {
		t.Errorf("pidSelectorFlags: expected: 0x3 actual %v\n", flags)
	}
	pid.IsNamespacePID = false
	if flags := pidSelectorFlags(pid); flags != 0x2 {
		t.Errorf("pidSelectorFlags: expected: 0x2 actual %v\n", flags)
	}
	pid.IsNamespacePID = true
	pid.FollowForks = false
	if flags := pidSelectorFlags(pid); flags != 0x1 {
		t.Errorf("pidSelectorFlags: expected: 0x1 actual %v\n", flags)
	}
	pid.IsNamespacePID = false
	pid.FollowForks = false
	if flags := pidSelectorFlags(pid); flags != 0x0 {
		t.Errorf("pidSelectorFlags: expected: 0x0 actual %v\n", flags)
	}
}

func TestPidSelectorValue(t *testing.T) {
	pid := &v1alpha1.PIDSelector{Operator: "In", Values: []uint32{1, 2, 3}, IsNamespacePID: true, FollowForks: true}
	expected := []byte{0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0}
	if b, l := pidSelectorValue(pid); bytes.Equal(b, expected) == false || l != 12 {
		t.Errorf("pidSelectorValue: expected %v actual %v\n", expected, b)
	}
}

func TestNamespaceValue(t *testing.T) {
	nstype := "Pid"
	ns := &v1alpha1.NamespaceSelector{Namespace: nstype, Operator: "In", Values: []string{"1", "2", "3"}}
	expected := []byte{0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0}
	if b, l, _ := namespaceSelectorValue(ns, strings.ToLower(nstype)); bytes.Equal(b, expected) == false || l != 12 {
		t.Errorf("namespaceSelectorValue: expected %v actual %v\n", expected, b)
	}
}

func TestNamespaceValueStr(t *testing.T) {
	nstype := "Pid"
	ns := &v1alpha1.NamespaceSelector{Namespace: nstype, Operator: "In", Values: []string{"host_ns"}}
	expected := []byte{252, 255, 255, 239}
	if b, l, _ := namespaceSelectorValue(ns, strings.ToLower(nstype)); bytes.Equal(b, expected) == false || l != 4 {
		t.Errorf("namespaceSelectorValue: expected %v actual %v\n", expected, b)
	}
}

func TestParseMatchArg(t *testing.T) {
	sig := []v1alpha1.KProbeArg{
		v1alpha1.KProbeArg{Index: 1, Type: "string", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 2, Type: "int", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 3, Type: "char_buf", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 4, Type: "char_iovec", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 5, Type: "sock", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 6, Type: "skb", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 7, Type: "skb", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 8, Type: "sock", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 9, Type: "sockaddr", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 10, Type: "socket", SizeArgIndex: 0, ReturnCopy: false},
	}

	arg1 := &v1alpha1.ArgSelector{Index: 1, Operator: "Equal", Values: []string{"foobar"}}
	k := NewKernelSelectorState(nil, nil)
	d := &k.data

	expected1 := []byte{
		0x00, 0x00, 0x00, 0x00, // Index == 0
		0x03, 0x00, 0x00, 0x00, // operator == equal
		52, 0x00, 0x00, 0x00, // length == 32
		0x06, 0x00, 0x00, 0x00, // value type == string
		0x00, 0x00, 0x00, 0x00, // map ID for strings <25
		0xff, 0xff, 0xff, 0xff, // map ID for strings 25-48
		0xff, 0xff, 0xff, 0xff, // map ID for strings 49-72
		0xff, 0xff, 0xff, 0xff, // map ID for strings 73-96
		0xff, 0xff, 0xff, 0xff, // map ID for strings 97-120
		0xff, 0xff, 0xff, 0xff, // map ID for strings 121-144
		0xff, 0xff, 0xff, 0xff, // map ID for strings 145-256
		0xff, 0xff, 0xff, 0xff, // map ID for strings 257-512
		0xff, 0xff, 0xff, 0xff, // map ID for strings 513-1024
		0xff, 0xff, 0xff, 0xff, // map ID for strings 1025-2048
		0xff, 0xff, 0xff, 0xff, // map ID for strings 2049-4096
	}
	if err := ParseMatchArg(k, arg1, sig); err != nil || bytes.Equal(expected1, d.e[0:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected:\n%v\nbytes:\n%v\nparsing %v\n", err, expected1, d.e[0:d.off], arg1)
	}

	nextArg := d.off
	arg2 := &v1alpha1.ArgSelector{Index: 2, Operator: "Equal", Values: []string{"1", "2"}}
	expected2 := []byte{
		0x01, 0x00, 0x00, 0x00, // Index == 1
		0x03, 0x00, 0x00, 0x00, // operator == equal
		16, 0x00, 0x00, 0x00, // length == 16
		0x01, 0x00, 0x00, 0x00, // value type == int
		0x01, 0x00, 0x00, 0x00, // value 1
		0x02, 0x00, 0x00, 0x00, // value 2
	}
	if err := ParseMatchArg(k, arg2, sig); err != nil || bytes.Equal(expected2, d.e[nextArg:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected2, d.e[nextArg:d.off], arg2)
	}

	nextArg = d.off
	arg3 := &v1alpha1.ArgSelector{Index: 5, Operator: "SAddr", Values: []string{"127.0.0.1", "10.1.2.3/24", "192.168.254.254/20"}}
	expected3 := []byte{
		0x04, 0x00, 0x00, 0x00, // Index == 4
		13, 0x00, 0x00, 0x00, // operator == saddr
		16, 0x00, 0x00, 0x00, // length == 16
		0x07, 0x00, 0x00, 0x00, // value type == sock
		0x00, 0x00, 0x00, 0x00, // Addr4LPM mapid = 0
		0xff, 0xff, 0xff, 0xff, // Addr6LPM no map
	}
	if err := ParseMatchArg(k, arg3, sig); err != nil || bytes.Equal(expected3, d.e[nextArg:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected3, d.e[nextArg:d.off], arg3)
	}

	nextArg = d.off
	arg4 := &v1alpha1.ArgSelector{Index: 6, Operator: "SPort", Values: []string{"8081", "25", "31337"}}
	expected4 := []byte{
		0x05, 0x00, 0x00, 0x00, // Index == 5
		15, 0x00, 0x00, 0x00, // operator == sport
		12, 0x00, 0x00, 0x00, // length == 12
		0x05, 0x00, 0x00, 0x00, // value type == skb
		0x00, 0x00, 0x00, 0x00, // argfilter mapid = 0
	}
	if err := ParseMatchArg(k, arg4, sig); err != nil || bytes.Equal(expected4, d.e[nextArg:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected4, d.e[nextArg:d.off], arg4)
	}

	nextArg = d.off
	arg5 := &v1alpha1.ArgSelector{Index: 7, Operator: "Protocol", Values: []string{"3", "IPPROTO_UDP", "IPPROTO_TCP"}}
	expected5 := []byte{
		0x06, 0x00, 0x00, 0x00, // Index == 6
		17, 0x00, 0x00, 0x00, // operator == protocol
		12, 0x00, 0x00, 0x00, // length == 12
		0x05, 0x00, 0x00, 0x00, // value type == skb
		1, 0x00, 0x00, 0x00, // argfilter mapid = 1
	}
	if err := ParseMatchArg(k, arg5, sig); err != nil || bytes.Equal(expected5, d.e[nextArg:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected5, d.e[nextArg:d.off], arg5)
	}

	nextArg = d.off
	arg6 := &v1alpha1.ArgSelector{Index: 8, Operator: "SAddr", Values: []string{"127.0.0.1", "::1/128"}}
	expected6 := []byte{
		0x07, 0x00, 0x00, 0x00, // Index == 7
		13, 0x00, 0x00, 0x00, // operator == saddr
		16, 0x00, 0x00, 0x00, // length == 16
		0x07, 0x00, 0x00, 0x00, // value type == sock
		1, 0x00, 0x00, 0x00, // Addr4LPM mapid = 1
		0x00, 0x00, 0x00, 0x00, // Addr6LPM mapid = 0
	}
	if err := ParseMatchArg(k, arg6, sig); err != nil || bytes.Equal(expected6, d.e[nextArg:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected6, d.e[nextArg:d.off], arg6)
	}

	nextArg = d.off
	arg7 := &v1alpha1.ArgSelector{Index: 9, Operator: "SAddr", Values: []string{"127.0.0.1", "::1/128"}}
	expected7 := []byte{
		0x08, 0x00, 0x00, 0x00, // Index == 8
		13, 0x00, 0x00, 0x00, // operator == saddr
		16, 0x00, 0x00, 0x00, // length == 16
		0x28, 0x00, 0x00, 0x00, // value type == sockaddr
		2, 0x00, 0x00, 0x00, // Addr4LPM mapid = 2
		1, 0x00, 0x00, 0x00, // Addr6LPM mapid = 1
	}
	if err := ParseMatchArg(k, arg7, sig); err != nil || bytes.Equal(expected7, d.e[nextArg:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected7, d.e[nextArg:d.off], arg7)
	}

	nextArg = d.off
	arg8 := &v1alpha1.ArgSelector{Index: 10, Operator: "SAddr", Values: []string{"127.0.0.1", "::1/128"}}
	expected8 := []byte{
		0x09, 0x00, 0x00, 0x00, // Index == 9
		13, 0x00, 0x00, 0x00, // operator == saddr
		16, 0x00, 0x00, 0x00, // length == 16
		0x29, 0x00, 0x00, 0x00, // value type == socket
		3, 0x00, 0x00, 0x00, // Addr4LPM mapid = 3
		2, 0x00, 0x00, 0x00, // Addr6LPM mapid = 2
	}
	if err := ParseMatchArg(k, arg8, sig); err != nil || bytes.Equal(expected8, d.e[nextArg:d.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected8, d.e[nextArg:d.off], arg8)
	}

	if config.EnableLargeProgs() { // multiple match args are supported only in kernels >= 5.4
		length := []byte{
			108, 0x00, 0x00, 0x00,
			24, 0x00, 0x00, 0x00,
			84, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		expected3 := append(length, expected1[:]...)
		expected3 = append(expected3, expected2[:]...)
		arg12 := []v1alpha1.ArgSelector{*arg1, *arg2}
		ks := NewKernelSelectorState(nil, nil)
		d = &ks.data
		if err := ParseMatchArgs(ks, arg12, sig); err != nil || bytes.Equal(expected3, d.e[0:d.off]) == false {
			t.Errorf("parseMatchArgs: error %v expected:\n%v\nbytes:\n%v\nparsing %v\n", err, expected3, d.e[0:d.off], arg3)
		}
	}
}

func TestParseMatchPid(t *testing.T) {
	pid1 := &v1alpha1.PIDSelector{Operator: "In", Values: []uint32{1, 2, 3}, IsNamespacePID: true, FollowForks: true}
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	expected1 := []byte{
		0x05, 0x00, 0x00, 0x00, // op == In
		0x03, 0x00, 0x00, 0x00, // flags == 0x3
		0x03, 0x00, 0x00, 0x00, // length == 0x3
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3
	}
	if err := ParseMatchPid(k, pid1); err != nil || bytes.Equal(expected1, d.e[0:d.off]) == false {
		t.Errorf("parseMatchPid: error %v expected %v bytes %v parsing %v\n", err, expected1, d.e[0:d.off], pid1)
	}

	nextPid := d.off
	pid2 := &v1alpha1.PIDSelector{Operator: "NotIn", Values: []uint32{1, 2, 3, 4}, IsNamespacePID: false, FollowForks: false}
	expected2 := []byte{
		0x06, 0x00, 0x00, 0x00, // op == NotIn
		0x00, 0x00, 0x00, 0x00, // flags == 0x0
		0x04, 0x00, 0x00, 0x00, // length == 0x4
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3
		0x04, 0x00, 0x00, 0x00, // Values[2] == 3
	}
	if err := ParseMatchPid(k, pid2); err != nil || bytes.Equal(expected2, d.e[nextPid:d.off]) == false {
		t.Errorf("parseMatchPid: error %v expected %v bytes %v parsing %v\n", err, expected2, d.e[nextPid:d.off], pid2)
	}

	length := []byte{56, 0x00, 0x00, 0x00}
	expected3 := append(length, expected1[:]...)
	expected3 = append(expected3, expected2[:]...)
	pid3 := []v1alpha1.PIDSelector{*pid1, *pid2}
	ks := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d = &ks.data
	if err := ParseMatchPids(ks, pid3); err != nil || bytes.Equal(expected3, d.e[0:d.off]) == false {
		t.Errorf("parseMatchPid: error %v expected %v bytes %v parsing %v\n", err, expected3, d.e[0:d.off], pid3)
	}
}

func TestParseMatchNamespaces(t *testing.T) {
	ns1 := &v1alpha1.NamespaceSelector{Namespace: "Pid", Operator: "In", Values: []string{"1", "2", "3"}}
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	expected1 := []byte{
		0x03, 0x00, 0x00, 0x00, // namespace == Pid
		0x05, 0x00, 0x00, 0x00, // op == In
		0x03, 0x00, 0x00, 0x00, // length == 0x3
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3
	}
	if err := ParseMatchNamespace(k, ns1); err != nil || bytes.Equal(expected1, d.e[0:d.off]) == false {
		t.Errorf("parseMatchNamespace: error %v expected %v bytes %v parsing %v\n", err, expected1, d.e[0:d.off], ns1)
	}

	nextPid := d.off
	ns2 := &v1alpha1.NamespaceSelector{Namespace: "Mnt", Operator: "NotIn", Values: []string{"1", "2", "3", "4"}}
	expected2 := []byte{
		0x02, 0x00, 0x00, 0x00, // namespace == Mnt
		0x06, 0x00, 0x00, 0x00, // op == NotIn
		0x04, 0x00, 0x00, 0x00, // length == 0x4
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3
		0x04, 0x00, 0x00, 0x00, // Values[2] == 3
	}
	if err := ParseMatchNamespace(k, ns2); err != nil || bytes.Equal(expected2, d.e[nextPid:d.off]) == false {
		t.Errorf("parseMatchNamespace: error %v expected %v bytes %v parsing %v\n", err, expected2, d.e[nextPid:d.off], ns2)
	}

	length := []byte{56, 0x00, 0x00, 0x00}
	expected3 := append(length, expected1[:]...)
	expected3 = append(expected3, expected2[:]...)
	ns3 := []v1alpha1.NamespaceSelector{*ns1, *ns2}
	ks := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d = &ks.data
	if err := ParseMatchNamespaces(ks, ns3); err != nil || bytes.Equal(expected3, d.e[0:d.off]) == false {
		t.Errorf("parseMatchNamespaces: error %v expected %v bytes %v parsing %v\n", err, expected3, d.e[0:d.off], ns3)
	}
}

func TestParseMatchNamespaceChanges(t *testing.T) {
	ns1 := &v1alpha1.NamespaceChangesSelector{Operator: "In", Values: []string{"Uts", "Mnt"}}
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	expected1 := []byte{
		0x05, 0x00, 0x00, 0x00, // op == In
		0x05, 0x00, 0x00, 0x00, // values
	}
	if err := ParseMatchNamespaceChange(k, ns1); err != nil || bytes.Equal(expected1, d.e[0:d.off]) == false {
		t.Errorf("parseMatchNamespaceChange: error %v expected %v bytes %v parsing %v\n", err, expected1, d.e[0:d.off], ns1)
	}
}

func TestParseMatchCapabilities(t *testing.T) {
	cap1 := &v1alpha1.CapabilitiesSelector{Type: "Effective", Operator: "In", IsNamespaceCapability: false, Values: []string{"CAP_CHOWN", "CAP_NET_RAW"}}
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	expected1 := []byte{
		0x01, 0x00, 0x00, 0x00, // Type == Effective
		0x05, 0x00, 0x00, 0x00, // op == In
		0x00, 0x00, 0x00, 0x00, // IsNamespaceCapability = false
		0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Values (uint64)
	}
	if err := ParseMatchCaps(k, cap1); err != nil || bytes.Equal(expected1, d.e[0:d.off]) == false {
		t.Errorf("parseMatchCaps: error %v expected %v bytes %v parsing %v\n", err, expected1, d.e[0:d.off], cap1)
	}

	nextPid := d.off
	cap2 := &v1alpha1.CapabilitiesSelector{Type: "Inheritable", Operator: "NotIn", IsNamespaceCapability: false, Values: []string{"CAP_SETPCAP", "CAP_SYS_ADMIN"}}
	expected2 := []byte{
		0x02, 0x00, 0x00, 0x00, // Type == Inheritable
		0x06, 0x00, 0x00, 0x00, // op == In
		0x00, 0x00, 0x00, 0x00, // IsNamespaceCapability = false
		0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // Values (uint64)
	}
	if err := ParseMatchCaps(k, cap2); err != nil || bytes.Equal(expected2, d.e[nextPid:d.off]) == false {
		t.Errorf("parseMatchCaps: error %v expected %v bytes %v parsing %v\n", err, expected2, d.e[nextPid:d.off], cap2)
	}

	length := []byte{44, 0x00, 0x00, 0x00}
	expected3 := append(length, expected1[:]...)
	expected3 = append(expected3, expected2[:]...)
	cap3 := []v1alpha1.CapabilitiesSelector{*cap1, *cap2}
	ks := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d = &ks.data
	if err := ParseMatchCapabilities(ks, cap3); err != nil || bytes.Equal(expected3, d.e[0:d.off]) == false {
		t.Errorf("parseMatchCapabilities: error %v expected %v bytes %v parsing %v\n", err, expected3, d.e[0:d.off], cap3)
	}
}

func TestParseMatchAction(t *testing.T) {
	// Create URL and FQDN tables to store URLs and FQDNs for this kprobe
	var actionArgTable idtable.Table

	act1 := &v1alpha1.ActionSelector{Action: "post"}
	act2 := &v1alpha1.ActionSelector{Action: "post"}
	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d := &k.data
	expected1 := []byte{
		0x00, 0x00, 0x00, 0x00, // Action = "post"
		0x00, 0x00, 0x00, 0x00, // DontRepeatFor = 0
		0x00, 0x00, 0x00, 0x00, // DontRepeatForScope = 0
		0x00, 0x00, 0x00, 0x00, // StackTrace = 0
		0x00, 0x00, 0x00, 0x00, // UserStackTrace = 0
		0x00, 0x00, 0x00, 0x00, // ImaHash = 0
	}
	if err := ParseMatchAction(k, act1, &actionArgTable); err != nil || bytes.Equal(expected1, d.e[0:d.off]) == false {
		t.Errorf("parseMatchAction: error %v expected %v bytes %v parsing %v\n", err, expected1, d.e[0:d.off], act1)
	}
	// This is a bit contrived because we only have single action so far
	// but once we get two we will update this. Point being we want to
	// test multiple actions.
	expected2 := []byte{
		0x00, 0x00, 0x00, 0x00, // Action = "post"
		0x00, 0x00, 0x00, 0x00, // DontRepeatFor = 0
		0x00, 0x00, 0x00, 0x00, // DontRepeatForScope = 0
		0x00, 0x00, 0x00, 0x00, // StackTrace = 0
		0x00, 0x00, 0x00, 0x00, // UserStackTrace = 0
		0x00, 0x00, 0x00, 0x00, // ImaHash = 0
	}
	length := []byte{52, 0x00, 0x00, 0x00}
	expected := append(length, expected1[:]...)
	expected = append(expected, expected2[:]...)

	act := []v1alpha1.ActionSelector{*act1, *act2}
	ks := &KernelSelectorState{data: KernelSelectorData{off: 0}}
	d = &ks.data
	if err := ParseMatchActions(ks, act, &actionArgTable); err != nil || bytes.Equal(expected, d.e[0:d.off]) == false {
		t.Errorf("parseMatchActions: error %v expected %v bytes %v parsing %v\n", err, expected, d.e[0:d.off], act)
	}
}

func TestParseMatchActionMax(t *testing.T) {
	var actionArgTable idtable.Table

	actions := []v1alpha1.ActionSelector{
		v1alpha1.ActionSelector{Action: "post"},
		v1alpha1.ActionSelector{Action: "post"},
		v1alpha1.ActionSelector{Action: "post"},
		v1alpha1.ActionSelector{Action: "post"},
	}

	k := &KernelSelectorState{data: KernelSelectorData{off: 0}}

	err := ParseMatchActions(k, actions, &actionArgTable)
	if err == nil {
		t.Errorf("ParseMatchActions expected to fail")
	}
}

// NB(kkourt):
func TestMultipleSelectorsExample(t *testing.T) {
	// Create URL and FQDN tables to store URLs and FQDNs for this kprobe
	var actionArgTable idtable.Table

	args := []v1alpha1.KProbeArg{
		{Index: 1, Type: "int", SizeArgIndex: 0, ReturnCopy: false},
	}

	pidSelector := []v1alpha1.PIDSelector{
		{Operator: "NotIn", Values: []uint32{33, 44}},
	}
	matchArgs := []v1alpha1.ArgSelector{
		{Index: 1, Operator: "Equal", Values: []string{"10", "20"}},
	}
	selectors := []v1alpha1.KProbeSelector{
		{MatchArgs: matchArgs, MatchPIDs: pidSelector},
		{MatchArgs: matchArgs, MatchPIDs: pidSelector},
	}
	b, _ := InitKernelSelectors(selectors, args, &actionArgTable)

	expected := make([]byte, 4096)
	expectedLen := 0
	expU32Push := func(i int) {
		binary.LittleEndian.PutUint32(expected[expectedLen:], uint32(i))
		expectedLen += 4
	}

	// value               absolute offset    explanation
	expU32Push(2)                 // off: 0       number of selectors
	expU32Push(8)                 // off: 4       relative ofset of 1st selector (4 + 8 = 12)
	expU32Push(104)               // off: 8       relative ofset of 2nd selector (8 + 124 = 132)
	expU32Push(100)               // off: 12      selector1: length (76 + 12 = 96)
	expU32Push(24)                // off: 16      selector1: MatchPIDs: len
	expU32Push(SelectorOpNotIn)   // off: 20      selector1: MatchPIDs[0]: op
	expU32Push(0)                 // off: 24      selector1: MatchPIDs[0]: flags
	expU32Push(2)                 // off: 28      selector1: MatchPIDs[0]: number of values
	expU32Push(33)                // off: 32      selector1: MatchPIDs[0]: val1
	expU32Push(44)                // off: 36      selector1: MatchPIDs[0]: val2
	expU32Push(4)                 // off: 40      selector1: MatchNamespaces: len
	expU32Push(4)                 // off: 44      selector1: MatchCapabilities: len
	expU32Push(4)                 // off: 48      selecotr1: MatchCurrentCred: len
	expU32Push(4)                 // off: 52      selector1: MatchNamespaceChanges: len
	expU32Push(4)                 // off: 56      selector1: MatchCapabilityChanges: len
	expU32Push(48)                // off: 84      selector1: matchArgs: len
	expU32Push(24)                // off: 88      selector1: matchArgs[0]: offset
	expU32Push(0)                 // off: 92      selector1: matchArgs[1]: offset
	expU32Push(0)                 // off: 96      selector1: matchArgs[2]: offset
	expU32Push(0)                 // off: 100     selector1: matchArgs[3]: offset
	expU32Push(0)                 // off: 104     selector1: matchArgs[4]: offset
	expU32Push(0)                 // off: 108     selector1: matchArgs: arg0: index
	expU32Push(SelectorOpEQ)      // off: 112     selector1: matchArgs: arg0: operator
	expU32Push(16)                // off: 116     selector1: matchArgs: arg0: len of vals
	expU32Push(gt.GenericIntType) // off: 120     selector1: matchArgs: arg0: type
	expU32Push(10)                // off: 124     selector1: matchArgs: arg0: val0: 10
	expU32Push(20)                // off: 128     selector1: matchArgs: arg0: val1: 20
	expU32Push(4)                 // off: 132     selector1: matchActions: length
	expU32Push(100)               // off: 136     selector2: length
	// ... everything else should be the same as selector1 ...

	if bytes.Equal(expected[:expectedLen], b[:expectedLen]) == false {
		t.Errorf("\ngot: %v\nexp: %v\n", expected[:expectedLen], b[:expectedLen])
	}
}

func TestInitKernelSelectors(t *testing.T) {
	expected_header := []byte{
		// spec header
		0x01, 0x00, 0x00, 0x00, // single selector

		0x04, 0x00, 0x00, 0x00, // selector offset list
	}

	expected_selsize_small := []byte{
		0x1c, 0x01, 0x00, 0x00, // size = pids + args + actions + namespaces + capabilities +  matchCurrentCred + 4
	}

	expected_selsize_large := []byte{
		0x7c, 0x01, 0x00, 0x00, // size = pids + args + actions + namespaces + capabilities + matchCurrentCred + namespacesChanges + capabilityChanges + 4
	}

	expected_filters_1 := []byte{
		// pid header
		56, 0x00, 0x00, 0x00, // size = sizeof(pid2) + sizeof(pid1) + 4

		//pid1 size = 24
		0x05, 0x00, 0x00, 0x00, // op == In
		0x03, 0x00, 0x00, 0x00, // flags == 0x3
		0x03, 0x00, 0x00, 0x00, // length == 0x3
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3

		//pid2 size = 28
		0x06, 0x00, 0x00, 0x00, // op == NotIn
		0x00, 0x00, 0x00, 0x00, // flags == 0x0
		0x04, 0x00, 0x00, 0x00, // length == 0x4
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3
		0x04, 0x00, 0x00, 0x00, // Values[2] == 3

		// namespace header
		44, 0x00, 0x00, 0x00, // size = sizeof(ns1) + sizeof(ns2) + 4

		// ns1 size = 24
		0x03, 0x00, 0x00, 0x00, // namespace == Pid
		0x05, 0x00, 0x00, 0x00, // op == In
		0x03, 0x00, 0x00, 0x00, // length == 0x3
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3

		// ns2 size = 16
		0x05, 0x00, 0x00, 0x00, // namespace == Net
		0x06, 0x00, 0x00, 0x00, // op == NotIn
		0x01, 0x00, 0x00, 0x00, // length == 0x1
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1

	}

	expected_filters_2 := []byte{
		// capabilities header
		44, 0x00, 0x00, 0x00, // size = sizeof(cap1) + sizeof(cap2) + 4

		// cap1 size = 20
		0x01, 0x00, 0x00, 0x00, // Type == Effective
		0x05, 0x00, 0x00, 0x00, // op == In
		0x00, 0x00, 0x00, 0x00, // IsNamespaceCapability = false
		0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Values (uint64)

		// cap2 size = 20
		0x02, 0x00, 0x00, 0x00, // Type == Inheritable
		0x06, 0x00, 0x00, 0x00, // op == In
		0x00, 0x00, 0x00, 0x00, // IsNamespaceCapability = false
		0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // Values (uint64)
	}

	expected_match_current_cred := []byte{}

	if !config.EnableLargeProgs() {
		// matchCurrentCred header
		expected_match_current_cred_body := []byte{
			4, 0x00, 0x00, 0x00, // size = flags + sizeof(Ruid) + sizeof(Euid) + ... + 4
		}
		expected_match_current_cred = append(expected_match_current_cred, expected_match_current_cred_body...)
	} else {
		// matchCurrentCred flags
		expected_match_current_cred_body := []byte{
			48, 0x00, 0x00, 0x00, // size = flags + sizeof(Ruid) + sizeof(Euid) + ... + 4
			0x01, 0x00, 0x00, 0x00, // flags
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Ruid
			0x03, 0x00, 0x00, 0x00, // op == Equal
			0x03, 0x00, 0x00, 0x00, // length == 0x3
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 1:1
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0:0
			0xe8, 0x03, 0x00, 0x00, 0xd0, 0x07, 0x00, 0x00, // 1000:2000
		}
		expected_match_current_cred = append(expected_match_current_cred, expected_match_current_cred_body...)
	}

	expected_changes_empty := []byte{
		// namespace changes header
		0x04, 0x00, 0x00, 0x00,

		// capability changes header
		0x04, 0x00, 0x00, 0x00,
	}

	expected_changes := []byte{
		// namespace changes header
		12, 0x00, 0x00, 0x00, // size = sizeof(nc1) + sizeof(nc2) + 4

		// nc1 size = 8
		0x05, 0x00, 0x00, 0x00, // op == In
		0x05, 0x00, 0x00, 0x00, // values

		// capability changes header
		24, 0x00, 0x00, 0x00, // size = sizeof(cap1) + sizeof(cap2) + 4

		// cap size = 20
		0x01, 0x00, 0x00, 0x00, // Type == Effective
		0x05, 0x00, 0x00, 0x00, // op == In
		0x00, 0x00, 0x00, 0x00, // IsNamespaceCapability = false
		0x00, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // Values (uint64)
	}

	expected_last_large := []byte{
		// arg header
		108, 0x00, 0x00, 0x00, // size = sizeof(arg2) + sizeof(arg1) + 24
		24, 0x00, 0x00, 0x00, // arg[0] offset
		84, 0x00, 0x00, 0x00, // arg[1] offset
		0x00, 0x00, 0x00, 0x00, // arg[2] offset
		0x00, 0x00, 0x00, 0x00, // arg[3] offset
		0x00, 0x00, 0x00, 0x00, // arg[4] offset

		//arg1 size = 60
		0x00, 0x00, 0x00, 0x00, // Index == 0
		0x03, 0x00, 0x00, 0x00, // operator == equal
		52, 0x00, 0x00, 0x00, // length == 32
		0x06, 0x00, 0x00, 0x00, // value type == string
		0x00, 0x00, 0x00, 0x00, // map ID for strings <25
		0xff, 0xff, 0xff, 0xff, // map ID for strings 25-48
		0xff, 0xff, 0xff, 0xff, // map ID for strings 49-72
		0xff, 0xff, 0xff, 0xff, // map ID for strings 73-96
		0xff, 0xff, 0xff, 0xff, // map ID for strings 97-120
		0xff, 0xff, 0xff, 0xff, // map ID for strings 121-144
		0xff, 0xff, 0xff, 0xff, // map ID for strings 145-256
		0xff, 0xff, 0xff, 0xff, // map ID for strings 257-512
		0xff, 0xff, 0xff, 0xff, // map ID for strings 513-1024
		0xff, 0xff, 0xff, 0xff, // map ID for strings 1025-2048
		0xff, 0xff, 0xff, 0xff, // map ID for strings 2049-4096

		//arg2 size = 24
		0x01, 0x00, 0x00, 0x00, // Index == 1
		0x03, 0x00, 0x00, 0x00, // operator == equal
		16, 0x00, 0x00, 0x00, // length == 0x10
		0x01, 0x00, 0x00, 0x00, // value type == int
		0x01, 0x00, 0x00, 0x00, // value 1
		0x02, 0x00, 0x00, 0x00, // value 2

		// actions header
		40, 0x00, 0x00, 0x00, // size = (6 * sizeof(uint32) * number of actions) + args
		0x00, 0x00, 0x00, 0x00, // post to userspace
		0x00, 0x00, 0x00, 0x00, // DontRepeatFor = 0
		0x00, 0x00, 0x00, 0x00, // DontRepeatForScope = 0
		0x00, 0x00, 0x00, 0x00, // StackTrace = 0
		0x00, 0x00, 0x00, 0x00, // UserStackTrace = 0
		0x00, 0x00, 0x00, 0x00, // ImaHash = 0
		0x01, 0x00, 0x00, 0x00, // fdinstall
		0x00, 0x00, 0x00, 0x00, // arg index of fd
		0x01, 0x00, 0x00, 0x00, // arg index of string filename
	}

	expected_last_small := []byte{
		// arg header
		84, 0x00, 0x00, 0x00, // size = sizeof(arg1) + 24
		24, 0x00, 0x00, 0x00, // arg[0] offset
		0x00, 0x00, 0x00, 0x00, // arg[1] offset
		0x00, 0x00, 0x00, 0x00, // arg[2] offset
		0x00, 0x00, 0x00, 0x00, // arg[3] offset
		0x00, 0x00, 0x00, 0x00, // arg[4] offset

		//arg1 size = 60
		0x00, 0x00, 0x00, 0x00, // Index == 0
		0x03, 0x00, 0x00, 0x00, // operator == equal
		52, 0x00, 0x00, 0x00, // length == 32
		0x06, 0x00, 0x00, 0x00, // value type == string
		0x00, 0x00, 0x00, 0x00, // map ID for strings <25
		0xff, 0xff, 0xff, 0xff, // map ID for strings 25-48
		0xff, 0xff, 0xff, 0xff, // map ID for strings 49-72
		0xff, 0xff, 0xff, 0xff, // map ID for strings 73-96
		0xff, 0xff, 0xff, 0xff, // map ID for strings 97-120
		0xff, 0xff, 0xff, 0xff, // map ID for strings 121-144
		0xff, 0xff, 0xff, 0xff, // map ID for strings 145-256
		0xff, 0xff, 0xff, 0xff, // map ID for strings 257-512
		0xff, 0xff, 0xff, 0xff, // map ID for strings 513-1024
		0xff, 0xff, 0xff, 0xff, // map ID for strings 1025-2048
		0xff, 0xff, 0xff, 0xff, // map ID for strings 2049-4096

		// actions header
		40, 0x00, 0x00, 0x00, // size = (6 * sizeof(uint32) * number of actions) + args + 4
		0x00, 0x00, 0x00, 0x00, // post to userspace
		0x00, 0x00, 0x00, 0x00, // DontRepeatFor = 0
		0x00, 0x00, 0x00, 0x00, // DontRepeatForScope = 0
		0x00, 0x00, 0x00, 0x00, // StackTrace = 0
		0x00, 0x00, 0x00, 0x00, // UserStackTrace = 0
		0x00, 0x00, 0x00, 0x00, // ImaHash = 0
		0x01, 0x00, 0x00, 0x00, // fdinstall
		0x00, 0x00, 0x00, 0x00, // arg index of fd
		0x01, 0x00, 0x00, 0x00, // arg index of string filename
	}

	expected := expected_header
	if config.EnableLargeProgs() {
		expected = append(expected, expected_selsize_large...)
		expected = append(expected, expected_filters_1...)
		expected = append(expected, expected_filters_2...)
		expected = append(expected, expected_match_current_cred...)
		expected = append(expected, expected_changes...)
		expected = append(expected, expected_last_large...)
	} else {
		expected = append(expected, expected_selsize_small...)
		expected = append(expected, expected_filters_1...)
		expected = append(expected, expected_filters_2...)
		expected = append(expected, expected_match_current_cred...)
		expected = append(expected, expected_changes_empty...)
		expected = append(expected, expected_last_small...)
	}

	pid1 := &v1alpha1.PIDSelector{Operator: "In", Values: []uint32{1, 2, 3}, IsNamespacePID: true, FollowForks: true}
	pid2 := &v1alpha1.PIDSelector{Operator: "NotIn", Values: []uint32{1, 2, 3, 4}, IsNamespacePID: false, FollowForks: false}
	matchPids := []v1alpha1.PIDSelector{*pid1, *pid2}
	ns1 := &v1alpha1.NamespaceSelector{Namespace: "Pid", Operator: "In", Values: []string{"1", "2", "3"}}
	ns2 := &v1alpha1.NamespaceSelector{Namespace: "Net", Operator: "NotIn", Values: []string{"1"}}
	matchNamespaces := []v1alpha1.NamespaceSelector{*ns1, *ns2}

	credIdVal := &v1alpha1.CredIDValues{Operator: "Equal", Values: []string{"1:1", "0:0", "1000:2000"}}
	ruids := []v1alpha1.CredIDValues{*credIdVal}
	matchCurrentCred := []v1alpha1.CredentialsSelector{}
	if config.EnableLargeProgs() {
		ruid := &v1alpha1.CredentialsSelector{UIDs: ruids}
		matchCurrentCred = append(matchCurrentCred, *ruid)
	}

	cap1 := &v1alpha1.CapabilitiesSelector{Type: "Effective", Operator: "In", IsNamespaceCapability: false, Values: []string{"CAP_CHOWN", "CAP_NET_RAW"}}
	cap2 := &v1alpha1.CapabilitiesSelector{Type: "Inheritable", Operator: "NotIn", IsNamespaceCapability: false, Values: []string{"CAP_SETPCAP", "CAP_SYS_ADMIN"}}
	matchCapabilities := []v1alpha1.CapabilitiesSelector{*cap1, *cap2}
	matchNamespaceChanges := []v1alpha1.NamespaceChangesSelector{}
	if config.EnableLargeProgs() {
		nc := &v1alpha1.NamespaceChangesSelector{Operator: "In", Values: []string{"Uts", "Mnt"}}
		matchNamespaceChanges = append(matchNamespaceChanges, *nc)
	}
	matchCapabilityChanges := []v1alpha1.CapabilitiesSelector{}
	if config.EnableLargeProgs() {
		cc := &v1alpha1.CapabilitiesSelector{Type: "Effective", Operator: "In", IsNamespaceCapability: false, Values: []string{"CAP_SYS_ADMIN", "CAP_NET_RAW"}}
		matchCapabilityChanges = append(matchCapabilityChanges, *cc)
	}
	var matchArgs []v1alpha1.ArgSelector
	if config.EnableLargeProgs() {
		arg1 := &v1alpha1.ArgSelector{Index: 1, Operator: "Equal", Values: []string{"foobar"}}
		arg2 := &v1alpha1.ArgSelector{Index: 2, Operator: "Equal", Values: []string{"1", "2"}}
		matchArgs = []v1alpha1.ArgSelector{*arg1, *arg2}
	} else {
		arg1 := &v1alpha1.ArgSelector{Index: 1, Operator: "Equal", Values: []string{"foobar"}}
		matchArgs = []v1alpha1.ArgSelector{*arg1}
	}
	act1 := &v1alpha1.ActionSelector{Action: "post"}
	act2 := &v1alpha1.ActionSelector{Action: "followfd",
		ArgFd:   0,
		ArgName: 1}
	matchActions := []v1alpha1.ActionSelector{*act1, *act2}

	selectors := []v1alpha1.KProbeSelector{
		{
			MatchPIDs:              matchPids,
			MatchNamespaces:        matchNamespaces,
			MatchCapabilities:      matchCapabilities,
			MatchCurrentCred:       matchCurrentCred,
			MatchNamespaceChanges:  matchNamespaceChanges,
			MatchCapabilityChanges: matchCapabilityChanges,
			MatchArgs:              matchArgs,
			MatchActions:           matchActions,
		},
	}
	args := []v1alpha1.KProbeArg{
		v1alpha1.KProbeArg{Index: 1, Type: "string", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 2, Type: "int", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 3, Type: "char_buf", SizeArgIndex: 0, ReturnCopy: false},
		v1alpha1.KProbeArg{Index: 4, Type: "char_iovec", SizeArgIndex: 0, ReturnCopy: false},
	}

	// Create URL and FQDN tables to store URLs and FQDNs for this kprobe
	var actionArgTable idtable.Table

	b, _ := InitKernelSelectors(selectors, args, &actionArgTable)
	if bytes.Equal(expected[0:], b[0:len(expected)]) == false {
		t.Errorf("InitKernelSelectors:\nexpected %v\nbytes    %v\n", expected, b[0:len(expected)])
	}
}

func TestReturnSelectorEmpty(t *testing.T) {
	var actionArgTable idtable.Table

	// empty selector
	// - MatchReturnArgs:    no matching return args
	// - MatchReturnActions: no return actions
	selectors := []v1alpha1.KProbeSelector{}

	b, _ := InitKernelReturnSelectors(selectors, nil, &actionArgTable)

	expected := make([]byte, 4096)
	expectedLen := 0
	expU32Push := func(i int) {
		binary.LittleEndian.PutUint32(expected[expectedLen:], uint32(i))
		expectedLen += 4
	}

	expU32Push(0) // off: 0       number of selectors

	if bytes.Equal(expected[:expectedLen], b[:expectedLen]) == false {
		t.Errorf("\ngot: %v\nexp: %v\n", b[:expectedLen], expected[:expectedLen])
	}
}

func TestReturnSelectorArgInt(t *testing.T) {
	var actionArgTable idtable.Table

	returnArg := v1alpha1.KProbeArg{Index: 0, Type: "int", SizeArgIndex: 0, ReturnCopy: false}

	matchReturnArgs := []v1alpha1.ArgSelector{
		{Index: 0, Operator: "Equal", Values: []string{"10", "20"}},
	}

	// selector
	// - MatchReturnArgs:    matching return int argument for 10,20 values
	// - MatchReturnActions: no return actions
	selectors := []v1alpha1.KProbeSelector{
		{MatchReturnArgs: matchReturnArgs},
	}

	b, _ := InitKernelReturnSelectors(selectors, &returnArg, &actionArgTable)

	expected := make([]byte, 4096)
	expectedLen := 0
	expU32Push := func(i int) {
		binary.LittleEndian.PutUint32(expected[expectedLen:], uint32(i))
		expectedLen += 4
	}

	expU32Push(1)                 // off: 0       number of selectors
	expU32Push(4)                 // off: 4       relative ofset of selector (4 + 4 = 8)
	expU32Push(56)                // off: 8       selector: length
	expU32Push(48)                // off: 12      selector: matchReturnArgs length
	expU32Push(24)                // off: 16      selector: matchReturnArgs arg offset[0]
	expU32Push(0)                 // off: 20      selector: matchReturnArgs arg offset[1]
	expU32Push(0)                 // off: 24      selector: matchReturnArgs arg offset[2]
	expU32Push(0)                 // off: 28      selector: matchReturnArgs arg offset[3]
	expU32Push(0)                 // off: 32      selector: matchReturnArgs arg offset[4]
	expU32Push(0)                 // off: 36      selector: matchReturnArgs[0].Index
	expU32Push(SelectorOpEQ)      // off: 40      selector: matchReturnArgs[0].Operator
	expU32Push(16)                // off: 44      selector: length (4 + 3*4) = 16
	expU32Push(gt.GenericIntType) // off: 48      selector: matchReturnArgs[0].Type
	expU32Push(10)                // off: 52      selector: matchReturnArgs[0].Values[0]
	expU32Push(20)                // off: 56      selector: matchReturnArgs[0].Values[1]
	expU32Push(4)                 // off: 60      selector: MatchActions length

	if bytes.Equal(expected[:expectedLen], b[:expectedLen]) == false {
		t.Errorf("\ngot: %v\nexp: %v\n", b[:expectedLen], expected[:expectedLen])
	}
}

func TestReturnSelectorArgIntActionFollowfd(t *testing.T) {
	var actionArgTable idtable.Table

	returnArg := v1alpha1.KProbeArg{Index: 0, Type: "int", SizeArgIndex: 0, ReturnCopy: false}

	act1 := v1alpha1.ActionSelector{Action: "post"}
	act2 := v1alpha1.ActionSelector{Action: "followfd",
		ArgFd:   7,
		ArgName: 8}

	matchReturnActions := []v1alpha1.ActionSelector{act1, act2}

	// selector
	// - MatchReturnArgs:    no matching return args
	// - MatchReturnActions: followfd, post actions
	selectors := []v1alpha1.KProbeSelector{
		{MatchReturnActions: matchReturnActions},
	}

	b, _ := InitKernelReturnSelectors(selectors, &returnArg, &actionArgTable)

	expected := make([]byte, 4096)
	expectedLen := 0
	expU32Push := func(i int) {
		binary.LittleEndian.PutUint32(expected[expectedLen:], uint32(i))
		expectedLen += 4
	}

	expU32Push(1)  // off: 0       number of selectors
	expU32Push(4)  // off: 4       relative ofset of selector (4 + 4 = 8)
	expU32Push(68) // off: 8       selector: length
	expU32Push(24) // off: 12      selector: matchReturnArgs length
	expU32Push(0)  // off: 16      selector: matchReturnArgs arg offset[0]
	expU32Push(0)  // off: 20      selector: matchReturnArgs arg offset[1]
	expU32Push(0)  // off: 24      selector: matchReturnArgs arg offset[2]
	expU32Push(0)  // off: 28      selector: matchReturnArgs arg offset[3]
	expU32Push(0)  // off: 32      selector: matchReturnArgs arg offset[4]
	expU32Push(40) // off: 36      selector: matchReturnActions length
	expU32Push(0)  // off: 40      selector: selectors.ActionTypePost
	expU32Push(0)  // off: 44      selector: rateLimit
	expU32Push(0)  // off: 44      selector: rateLimitScope
	expU32Push(0)  // off: 48      selector: stackTrace
	expU32Push(0)  // off: 52      selector: userStackTrace
	expU32Push(0)  // off: 56      selector: imaHash
	expU32Push(1)  // off: 60      selector: selectors.ActionTypeFollowFd
	expU32Push(7)  // off: 64      selector: action.ArgFd
	expU32Push(8)  // off: 68      selector: action.ArgName

	if bytes.Equal(expected[:expectedLen], b[:expectedLen]) == false {
		t.Errorf("\ngot: %v\nexp: %v\n", b[:expectedLen], expected[:expectedLen])
	}
}

func TestParseAddr(t *testing.T) {
	tests := map[string]struct {
		addrStr         string
		expectedAddr    []byte
		expectedMaskLen uint32
		expectedErr     string
	}{
		"invalid address format": {
			addrStr:     "1.2.3.4/16/16",
			expectedErr: "CIDR is invalid",
		},
		"invalid ipv4 cidr": {
			addrStr:     "a.b.c.d/16",
			expectedErr: "CIDR is invalid",
		},
		"invalid ipv6 cidr": {
			addrStr:     "::gg/16",
			expectedErr: "CIDR is invalid",
		},
		"invalid mask value": {
			addrStr:     "1.2.3.4/invalid",
			expectedErr: "CIDR is invalid",
		},
		"invalid ipv4 mask len": {
			addrStr:     "1.2.3.4/33",
			expectedErr: "CIDR is invalid",
		},
		"invalid ipv6 mask len": {
			addrStr:     "::1/256",
			expectedErr: "CIDR is invalid",
		},
		"invalid ipv4 address": {
			addrStr:     "a.b.c.d",
			expectedErr: "IP address is invalid",
		},
		"invalid ipv6 address": {
			addrStr:     "::gg",
			expectedErr: "IP address is invalid",
		},
		"valid ipv4": {
			addrStr:         "1.2.3.4",
			expectedAddr:    []byte{1, 2, 3, 4},
			expectedMaskLen: 32,
		},
		"valid ipv4 cidr": {
			addrStr:         "1.2.3.4/16",
			expectedAddr:    []byte{1, 2, 3, 4},
			expectedMaskLen: 16,
		},
		"valid ipv6": {
			addrStr:         "0102::0304",
			expectedAddr:    []byte{1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4},
			expectedMaskLen: 128,
		},
		"valid ipv6 cidr": {
			addrStr:         "0102::0304/64",
			expectedAddr:    []byte{1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4},
			expectedMaskLen: 64,
		},
		"valid ipv4-mapped ipv6": {
			addrStr:         "::ffff:1.2.3.4",
			expectedAddr:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4},
			expectedMaskLen: 128,
		},
		"valid ipv4-mapped ipv6 cidr": {
			addrStr:         "::ffff:1.2.3.4/96",
			expectedAddr:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4},
			expectedMaskLen: 96,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			addr, maskLen, err := parseAddr(test.addrStr)
			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
			} else {
				require.Equal(t, test.expectedAddr, addr)
				require.Equal(t, test.expectedMaskLen, maskLen)
			}
		})
	}
}

func TestParseCapabilityMask(t *testing.T) {
	v, err := parseCapabilitiesMask("100")
	require.NoError(t, err)
	assert.Equal(t, uint64(100), v)

	v, err = parseCapabilitiesMask("CAP_SYS_ADMIN")
	require.NoError(t, err)
	assert.Equal(t, (uint64(1) << 21), v)

	v, err = parseCapabilitiesMask("CAP_SYS_ADMIN,CAP_BPF")
	require.NoError(t, err)
	assert.Equal(t, (uint64(1)<<21)|(uint64(1)<<39), v)

	// NB: spaces should be OK
	v, err = parseCapabilitiesMask("CAP_SYS_ADMIN, CAP_BPF")
	require.NoError(t, err)
	assert.Equal(t, (uint64(1)<<21)|(uint64(1)<<39), v)

	_, err = parseCapabilitiesMask("CAP_PIZZA")
	assert.Error(t, err)
}
