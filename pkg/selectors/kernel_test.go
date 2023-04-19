// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// go test -gcflags="" -c ./pkg/selectors -o go-tests/selectors.test
// sudo ./go-tests/selectors.test  [ -test.run TestCopyFileRange ]

package selectors

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
)

func TestWriteSelectorUint32(t *testing.T) {
	k := &KernelSelectorState{off: 0}
	v := uint32(0x1234abcd)
	WriteSelectorUint32(k, v)
	if k.e[3] != 0x12 || k.e[2] != 0x34 || k.e[1] != 0xab || k.e[0] != 0xcd {
		t.Errorf("SelectorStateWrite failed: %x %x %x %x\n",
			k.e[0], k.e[1], k.e[2], k.e[3])
	}

	k.off = 1024
	WriteSelectorUint32(k, v)
	if k.e[1027] != 0x12 || k.e[1026] != 0x34 || k.e[1025] != 0xab || k.e[1024] != 0xcd {
		t.Errorf("SelectorStateWrite offset(1024) failed: %x %x %x %x\n",
			k.e[1027], k.e[1026], k.e[1025], k.e[1024])
	}
}

func TestWriteSelectorLength(t *testing.T) {
	k := &KernelSelectorState{off: 0}
	v := uint32(0x1234abcd)

	e1 := 8
	e2 := 12

	off := AdvanceSelectorLength(k)
	WriteSelectorUint32(k, v)
	WriteSelectorLength(k, off)

	off = AdvanceSelectorLength(k)
	WriteSelectorUint32(k, v)
	WriteSelectorUint32(k, v)
	WriteSelectorLength(k, off)

	// Length fields include the length value
	if k.e[3] != 0 || k.e[2] != 0 || k.e[1] != 0 || k.e[0] != 8 {
		t.Errorf("WriteSelectorLength(0): expected %d actual 0X%x%x%x%x\n", e1, k.e[0], k.e[1], k.e[2], k.e[3])
	}
	if k.e[11] != 0 || k.e[10] != 0 || k.e[9] != 0 || k.e[8] != 12 {
		t.Errorf("WriteSelectorLength(8): expected %d actual 0X%x%x%x%x\n", e2, k.e[8], k.e[9], k.e[10], k.e[11])
	}
}

func TestWriteSelectorByteArray(t *testing.T) {
	k := &KernelSelectorState{off: 0}
	v := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

	off1 := AdvanceSelectorLength(k)
	off2 := AdvanceSelectorLength(k)
	WriteSelectorByteArray(k, v, uint32(len(v)))
	WriteSelectorLength(k, off2)
	WriteSelectorLength(k, off1)

	// Length fields include the length value
	if k.e[3] != 0 || k.e[2] != 0 || k.e[1] != 0 || k.e[0] != 23 {
		t.Errorf("WriteSelectorLength(0): expected 0X%x actual 0X%x%x%x%x\n", 23, k.e[0], k.e[1], k.e[2], k.e[3])
	}
	if k.e[7] != 0 || k.e[6] != 0 || k.e[5] != 0 || k.e[4] != 19 {
		t.Errorf("WriteSelectorLength(8): expected 0X%x actual 0X%x%x%x%x\n", 19, k.e[4], k.e[5], k.e[6], k.e[7])
	}
	// Byte array
	if k.e[8] != 1 || k.e[9] != 2 || k.e[10] != 3 || k.e[11] != 4 ||
		k.e[12] != 5 || k.e[13] != 6 || k.e[14] != 7 || k.e[15] != 8 ||
		k.e[16] != 9 || k.e[17] != 0xa || k.e[18] != 0xb || k.e[19] != 0xc ||
		k.e[20] != 0xd || k.e[21] != 0xe || k.e[22] != 0xf {
		t.Errorf("WriteSelectorLength(8): expected %x actual 0X%x\n", v, k.e[8:])
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
	if op, err := SelectorOp("foo"); op != 0 || err == nil {
		t.Errorf("selectorOp: expected error actual %d %v\n", op, err)
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
	}

	arg1 := &v1alpha1.ArgSelector{Index: 1, Operator: "Equal", Values: []string{"foobar"}}
	k := &KernelSelectorState{off: 0}
	expected1 := []byte{
		0x01, 0x00, 0x00, 0x00, // Index == 1
		0x03, 0x00, 0x00, 0x00, // operator == equal
		18, 0x00, 0x00, 0x00, // length == 18
		0x06, 0x00, 0x00, 0x00, // value type == string
		0x06, 0x00, 0x00, 0x00, // value length == 6
		102, 111, 111, 98, 97, 114, // value ascii "foobar"
	}
	if err := ParseMatchArg(k, arg1, sig); err != nil || bytes.Equal(expected1, k.e[0:k.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected1, k.e[0:k.off], arg1)
	}

	nextArg := k.off
	arg2 := &v1alpha1.ArgSelector{Index: 2, Operator: "Equal", Values: []string{"1", "2"}}
	expected2 := []byte{
		0x02, 0x00, 0x00, 0x00, // Index == 2
		0x03, 0x00, 0x00, 0x00, // operator == equal
		16, 0x00, 0x00, 0x00, // length == 16
		0x01, 0x00, 0x00, 0x00, // value type == int
		0x01, 0x00, 0x00, 0x00, // value 1
		0x02, 0x00, 0x00, 0x00, // value 2
	}
	if err := ParseMatchArg(k, arg2, sig); err != nil || bytes.Equal(expected2, k.e[nextArg:k.off]) == false {
		t.Errorf("parseMatchArg: error %v expected %v bytes %v parsing %v\n", err, expected2, k.e[nextArg:k.off], arg2)
	}

	if kernels.EnableLargeProgs() { // multiple match args are supported only in kernels >= 5.4
		length := []byte{
			74, 0x00, 0x00, 0x00,
			24, 0x00, 0x00, 0x00,
			50, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		expected3 := append(length, expected1[:]...)
		expected3 = append(expected3, expected2[:]...)
		arg3 := []v1alpha1.ArgSelector{*arg1, *arg2}
		ks := &KernelSelectorState{off: 0}
		if err := ParseMatchArgs(ks, arg3, sig); err != nil || bytes.Equal(expected3, ks.e[0:ks.off]) == false {
			t.Errorf("parseMatchArgs: error %v expected %v bytes %v parsing %v\n", err, expected3, ks.e[0:k.off], arg3)
		}
	}
}

func TestParseMatchPid(t *testing.T) {
	pid1 := &v1alpha1.PIDSelector{Operator: "In", Values: []uint32{1, 2, 3}, IsNamespacePID: true, FollowForks: true}
	k := &KernelSelectorState{off: 0}
	expected1 := []byte{
		0x05, 0x00, 0x00, 0x00, // op == In
		0x03, 0x00, 0x00, 0x00, // flags == 0x3
		0x03, 0x00, 0x00, 0x00, // length == 0x3
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3
	}
	if err := ParseMatchPid(k, pid1); err != nil || bytes.Equal(expected1, k.e[0:k.off]) == false {
		t.Errorf("parseMatchPid: error %v expected %v bytes %v parsing %v\n", err, expected1, k.e[0:k.off], pid1)
	}

	nextPid := k.off
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
	if err := ParseMatchPid(k, pid2); err != nil || bytes.Equal(expected2, k.e[nextPid:k.off]) == false {
		t.Errorf("parseMatchPid: error %v expected %v bytes %v parsing %v\n", err, expected2, k.e[nextPid:k.off], pid2)
	}

	length := []byte{56, 0x00, 0x00, 0x00}
	expected3 := append(length, expected1[:]...)
	expected3 = append(expected3, expected2[:]...)
	pid3 := []v1alpha1.PIDSelector{*pid1, *pid2}
	ks := &KernelSelectorState{off: 0}
	if err := ParseMatchPids(ks, pid3); err != nil || bytes.Equal(expected3, ks.e[0:ks.off]) == false {
		t.Errorf("parseMatchPid: error %v expected %v bytes %v parsing %v\n", err, expected3, ks.e[0:ks.off], pid3)
	}
}

func TestParseMatchNamespaces(t *testing.T) {
	ns1 := &v1alpha1.NamespaceSelector{Namespace: "Pid", Operator: "In", Values: []string{"1", "2", "3"}}
	k := &KernelSelectorState{off: 0}
	expected1 := []byte{
		0x03, 0x00, 0x00, 0x00, // namespace == Pid
		0x05, 0x00, 0x00, 0x00, // op == In
		0x03, 0x00, 0x00, 0x00, // length == 0x3
		0x01, 0x00, 0x00, 0x00, // Values[0] == 1
		0x02, 0x00, 0x00, 0x00, // Values[1] == 2
		0x03, 0x00, 0x00, 0x00, // Values[2] == 3
	}
	if err := ParseMatchNamespace(k, ns1); err != nil || bytes.Equal(expected1, k.e[0:k.off]) == false {
		t.Errorf("parseMatchNamespace: error %v expected %v bytes %v parsing %v\n", err, expected1, k.e[0:k.off], ns1)
	}

	nextPid := k.off
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
	if err := ParseMatchNamespace(k, ns2); err != nil || bytes.Equal(expected2, k.e[nextPid:k.off]) == false {
		t.Errorf("parseMatchNamespace: error %v expected %v bytes %v parsing %v\n", err, expected2, k.e[nextPid:k.off], ns2)
	}

	length := []byte{56, 0x00, 0x00, 0x00}
	expected3 := append(length, expected1[:]...)
	expected3 = append(expected3, expected2[:]...)
	ns3 := []v1alpha1.NamespaceSelector{*ns1, *ns2}
	ks := &KernelSelectorState{off: 0}
	if err := ParseMatchNamespaces(ks, ns3); err != nil || bytes.Equal(expected3, ks.e[0:ks.off]) == false {
		t.Errorf("parseMatchNamespaces: error %v expected %v bytes %v parsing %v\n", err, expected3, ks.e[0:ks.off], ns3)
	}
}

func TestParseMatchNamespaceChanges(t *testing.T) {
	ns1 := &v1alpha1.NamespaceChangesSelector{Operator: "In", Values: []string{"Uts", "Mnt"}}
	k := &KernelSelectorState{off: 0}
	expected1 := []byte{
		0x05, 0x00, 0x00, 0x00, // op == In
		0x05, 0x00, 0x00, 0x00, // values
	}
	if err := ParseMatchNamespaceChange(k, ns1); err != nil || bytes.Equal(expected1, k.e[0:k.off]) == false {
		t.Errorf("parseMatchNamespaceChange: error %v expected %v bytes %v parsing %v\n", err, expected1, k.e[0:k.off], ns1)
	}
}

func TestParseMatchCapabilities(t *testing.T) {
	cap1 := &v1alpha1.CapabilitiesSelector{Type: "Effective", Operator: "In", IsNamespaceCapability: false, Values: []string{"CAP_CHOWN", "CAP_NET_RAW"}}
	k := &KernelSelectorState{off: 0}
	expected1 := []byte{
		0x01, 0x00, 0x00, 0x00, // Type == Effective
		0x05, 0x00, 0x00, 0x00, // op == In
		0x00, 0x00, 0x00, 0x00, // IsNamespaceCapability = false
		0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Values (uint64)
	}
	if err := ParseMatchCaps(k, cap1); err != nil || bytes.Equal(expected1, k.e[0:k.off]) == false {
		t.Errorf("parseMatchCaps: error %v expected %v bytes %v parsing %v\n", err, expected1, k.e[0:k.off], cap1)
	}

	nextPid := k.off
	cap2 := &v1alpha1.CapabilitiesSelector{Type: "Inheritable", Operator: "NotIn", IsNamespaceCapability: false, Values: []string{"CAP_SETPCAP", "CAP_SYS_ADMIN"}}
	expected2 := []byte{
		0x02, 0x00, 0x00, 0x00, // Type == Inheritable
		0x06, 0x00, 0x00, 0x00, // op == In
		0x00, 0x00, 0x00, 0x00, // IsNamespaceCapability = false
		0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // Values (uint64)
	}
	if err := ParseMatchCaps(k, cap2); err != nil || bytes.Equal(expected2, k.e[nextPid:k.off]) == false {
		t.Errorf("parseMatchCaps: error %v expected %v bytes %v parsing %v\n", err, expected2, k.e[nextPid:k.off], cap2)
	}

	length := []byte{44, 0x00, 0x00, 0x00}
	expected3 := append(length, expected1[:]...)
	expected3 = append(expected3, expected2[:]...)
	cap3 := []v1alpha1.CapabilitiesSelector{*cap1, *cap2}
	ks := &KernelSelectorState{off: 0}
	if err := ParseMatchCapabilities(ks, cap3); err != nil || bytes.Equal(expected3, ks.e[0:ks.off]) == false {
		t.Errorf("parseMatchCapabilities: error %v expected %v bytes %v parsing %v\n", err, expected3, ks.e[0:ks.off], cap3)
	}
}

func TestParseMatchAction(t *testing.T) {
	// Create URL and FQDN tables to store URLs and FQDNs for this kprobe
	var actionArgTable idtable.Table

	act1 := &v1alpha1.ActionSelector{Action: "post"}
	act2 := &v1alpha1.ActionSelector{Action: "post"}
	k := &KernelSelectorState{off: 0}
	expected1 := []byte{
		0x00, 0x00, 0x00, 0x00, // Action = "post"
	}
	if err := ParseMatchAction(k, act1, &actionArgTable); err != nil || bytes.Equal(expected1, k.e[0:k.off]) == false {
		t.Errorf("parseMatchAction: error %v expected %v bytes %v parsing %v\n", err, expected1, k.e[0:k.off], act1)
	}
	// This is a bit contrived because we only have single action so far
	// but once we get two we will update this. Point being we want to
	// test multiple actions.
	expected2 := []byte{
		0x00, 0x00, 0x00, 0x00, // Action = "post"
	}
	length := []byte{12, 0x00, 0x00, 0x00}
	expected := append(length, expected1[:]...)
	expected = append(expected, expected2[:]...)

	act := []v1alpha1.ActionSelector{*act1, *act2}
	ks := &KernelSelectorState{off: 0}
	if err := ParseMatchActions(ks, act, &actionArgTable); err != nil || bytes.Equal(expected, ks.e[0:ks.off]) == false {
		t.Errorf("parseMatchActions: error %v expected %v bytes %v parsing %v\n", err, expected, ks.e[0:ks.off], act)
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

	k := &KernelSelectorState{off: 0}

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
	expU32Push(2)               // off: 0       number of selectors
	expU32Push(8)               // off: 4       relative ofset of 1st selector (4 + 8 = 12)
	expU32Push(100)             // off: 8       relative ofset of 2nd selector (8 + 124 = 132)
	expU32Push(96)              // off: 12      selector1: length (76 + 12 = 96)
	expU32Push(24)              // off: 16      selector1: MatchPIDs: len
	expU32Push(SelectorOpNotIn) // off: 20      selector1: MatchPIDs[0]: op
	expU32Push(0)               // off: 24      selector1: MatchPIDs[0]: flags
	expU32Push(2)               // off: 28      selector1: MatchPIDs[0]: number of values
	expU32Push(33)              // off: 32      selector1: MatchPIDs[0]: val1
	expU32Push(44)              // off: 36      selector1: MatchPIDs[0]: val2
	expU32Push(4)               // off: 40      selector1: MatchNamespaces: len
	expU32Push(4)               // off: 44      selector1: MatchCapabilities: len
	expU32Push(4)               // off: 48      selector1: MatchNamespaceChanges: len
	expU32Push(4)               // off: 52      selector1: MatchCapabilityChanges: len
	expU32Push(48)              // off: 80      selector1: matchArgs: len
	expU32Push(24)              // off: 84      selector1: matchArgs[0]: offset
	expU32Push(0)               // off: 88      selector1: matchArgs[1]: offset
	expU32Push(0)               // off: 92      selector1: matchArgs[2]: offset
	expU32Push(0)               // off: 96      selector1: matchArgs[3]: offset
	expU32Push(0)               // off: 100     selector1: matchArgs[4]: offset
	expU32Push(1)               // off: 104     selector1: matchArgs: arg0: index
	expU32Push(SelectorOpEQ)    // off: 108     selector1: matchArgs: arg0: operator
	expU32Push(16)              // off: 112     selector1: matchArgs: arg0: len of vals
	expU32Push(argTypeInt)      // off: 116     selector1: matchArgs: arg0: type
	expU32Push(10)              // off: 120     selector1: matchArgs: arg0: val0: 10
	expU32Push(20)              // off: 124     selector1: matchArgs: arg0: val1: 20
	expU32Push(4)               // off: 128     selector1: matchActions: length
	expU32Push(96)              // off: 132     selector2: length
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
		0xe2, 0x00, 0x00, 0x00, // size = pids + args + actions + namespaces + capabilities  + 4
	}

	expected_selsize_large := []byte{
		22, 0x01, 0x00, 0x00, // size = pids + args + actions + namespaces + namespacesChanges + capabilities + capabilityChanges + 4
	}

	expected_filters := []byte{
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
		74, 0x00, 0x00, 0x00, // size = sizeof(arg2) + sizeof(arg1) + 4
		24, 0x00, 0x00, 0x00, // arg[0] offset
		50, 0x00, 0x00, 0x00, // arg[1] offset
		0x00, 0x00, 0x00, 0x00, // arg[2] offset
		0x00, 0x00, 0x00, 0x00, // arg[3] offset
		0x00, 0x00, 0x00, 0x00, // arg[4] offset

		//arg1 size = 26
		0x01, 0x00, 0x00, 0x00, // Index == 1
		0x03, 0x00, 0x00, 0x00, // operator == equal
		18, 0x00, 0x00, 0x00, // length == 18
		0x06, 0x00, 0x00, 0x00, // value type == string
		0x06, 0x00, 0x00, 0x00, // value length == 6
		102, 111, 111, 98, 97, 114, // value ascii "foobar"

		//arg2 size = 24
		0x02, 0x00, 0x00, 0x00, // Index == 2
		0x03, 0x00, 0x00, 0x00, // operator == equal
		16, 0x00, 0x00, 0x00, // length == 0x10
		0x01, 0x00, 0x00, 0x00, // value type == int
		0x01, 0x00, 0x00, 0x00, // value 1
		0x02, 0x00, 0x00, 0x00, // value 2

		// actions header
		20, 0x00, 0x00, 0x00, // size = (sizeof(uint32) * number of actions)  + 4
		0x00, 0x00, 0x00, 0x00, // post to userspace
		0x01, 0x00, 0x00, 0x00, // fdinstall
		0x00, 0x00, 0x00, 0x00, // arg index of fd
		0x01, 0x00, 0x00, 0x00, // arg index of string filename
	}

	expected_last_small := []byte{
		// arg header
		50, 0x00, 0x00, 0x00, // size = sizeof(arg2) + sizeof(arg1) + 4
		24, 0x00, 0x00, 0x00, // arg[0] offset
		0x00, 0x00, 0x00, 0x00, // arg[1] offset
		0x00, 0x00, 0x00, 0x00, // arg[2] offset
		0x00, 0x00, 0x00, 0x00, // arg[3] offset
		0x00, 0x00, 0x00, 0x00, // arg[4] offset

		//arg1 size = 26
		0x01, 0x00, 0x00, 0x00, // Index == 1
		0x03, 0x00, 0x00, 0x00, // operator == equal
		18, 0x00, 0x00, 0x00, // length == 18
		0x06, 0x00, 0x00, 0x00, // value type == string
		0x06, 0x00, 0x00, 0x00, // value length == 6
		102, 111, 111, 98, 97, 114, // value ascii "foobar"

		// actions header
		20, 0x00, 0x00, 0x00, // size = (sizeof(uint32) * number of actions)  + 4
		0x00, 0x00, 0x00, 0x00, // post to userspace
		0x01, 0x00, 0x00, 0x00, // fdinstall
		0x00, 0x00, 0x00, 0x00, // arg index of fd
		0x01, 0x00, 0x00, 0x00, // arg index of string filename
	}

	expected := expected_header
	if kernels.EnableLargeProgs() {
		expected = append(expected, expected_selsize_large...)
		expected = append(expected, expected_filters...)
		expected = append(expected, expected_changes...)
		expected = append(expected, expected_last_large...)
	} else {
		expected = append(expected, expected_selsize_small...)
		expected = append(expected, expected_filters...)
		expected = append(expected, expected_changes_empty...)
		expected = append(expected, expected_last_small...)
	}

	pid1 := &v1alpha1.PIDSelector{Operator: "In", Values: []uint32{1, 2, 3}, IsNamespacePID: true, FollowForks: true}
	pid2 := &v1alpha1.PIDSelector{Operator: "NotIn", Values: []uint32{1, 2, 3, 4}, IsNamespacePID: false, FollowForks: false}
	matchPids := []v1alpha1.PIDSelector{*pid1, *pid2}
	ns1 := &v1alpha1.NamespaceSelector{Namespace: "Pid", Operator: "In", Values: []string{"1", "2", "3"}}
	ns2 := &v1alpha1.NamespaceSelector{Namespace: "Net", Operator: "NotIn", Values: []string{"1"}}
	matchNamespaces := []v1alpha1.NamespaceSelector{*ns1, *ns2}
	cap1 := &v1alpha1.CapabilitiesSelector{Type: "Effective", Operator: "In", IsNamespaceCapability: false, Values: []string{"CAP_CHOWN", "CAP_NET_RAW"}}
	cap2 := &v1alpha1.CapabilitiesSelector{Type: "Inheritable", Operator: "NotIn", IsNamespaceCapability: false, Values: []string{"CAP_SETPCAP", "CAP_SYS_ADMIN"}}
	matchCapabilities := []v1alpha1.CapabilitiesSelector{*cap1, *cap2}
	matchNamespaceChanges := []v1alpha1.NamespaceChangesSelector{}
	if kernels.EnableLargeProgs() {
		nc := &v1alpha1.NamespaceChangesSelector{Operator: "In", Values: []string{"Uts", "Mnt"}}
		matchNamespaceChanges = append(matchNamespaceChanges, *nc)
	}
	matchCapabilityChanges := []v1alpha1.CapabilitiesSelector{}
	if kernels.EnableLargeProgs() {
		cc := &v1alpha1.CapabilitiesSelector{Type: "Effective", Operator: "In", IsNamespaceCapability: false, Values: []string{"CAP_SYS_ADMIN", "CAP_NET_RAW"}}
		matchCapabilityChanges = append(matchCapabilityChanges, *cc)
	}
	var matchArgs []v1alpha1.ArgSelector
	if kernels.EnableLargeProgs() {
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
	if bytes.Equal(expected[0:len(expected)], b[0:len(expected)]) == false {
		t.Errorf("InitKernelSelectors: expected %v bytes %v\n", expected, b[0:len(expected)])
	}
}
