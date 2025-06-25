// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package stacktracetree

import (
	"fmt"
	"log"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/calltraceapi"
)

// Addr is an Address on the stacktrace tree
type Addr = uint64

// SttNode is a tree node
type SttNode struct {
	Addr     Addr
	Count    int
	Symbol   string
	Labels   map[string]int
	Children map[Addr]*SttNode
}

func (n *SttNode) merge(n2 *SttNode) {
	if n.Addr != n2.Addr {
		log.Fatalf("cannot merge incompatible nodes with addresses %x and %x", n.Addr, n2.Addr)
	}

	n.Count += n2.Count

	s1 := n.Symbol
	s2 := n2.Symbol

	// if s1 == "" && s2 == "" {
	// 	// nothing to do
	// } else if s1 != "" && s2 == "" {
	// 	// nothing to do
	if s1 == "" && s2 != "" {
		n.Symbol = s2
	} else if s1 != s2 {
		// both have symbols defined, but they are different, so
		// something is wrong
		log.Printf("error: different symbols (%s,%s) for the same address %x", s1, s2, n.Addr)
	}

	for lbl, lblCount := range n2.Labels {
		n.Labels[lbl] += lblCount
	}

	if len(n2.Children) > 0 {
		log.Fatal("TODO: implement children merging")
	}
}

// Sttree is a stacktrace tree
type Sttree struct {
	Root SttNode
}

// Stt is a single stacktrace
type Stt struct {
	nodes []*SttNode
}

// Append appends an entry to a stacktrace
func (p *Stt) Append(addr Addr, sym string, labels []string) {
	node := &SttNode{
		Addr:     addr,
		Count:    1,
		Symbol:   sym,
		Children: map[Addr]*SttNode{},
		Labels:   map[string]int{},
	}

	for _, label := range labels {
		node.Labels[label] = 1
	}

	p.nodes = append(p.nodes, node)
}

func SttFromCalltrace(calltrace []calltraceapi.StackAddr, labels []string) *Stt {
	stt := Stt{}
	for _, ct := range calltrace {
		stt.Append(ct.Addr, ct.Symbol, labels)
	}

	return &stt
}

// CreateSttree creates a stacktrace tree
func CreateSttree() *Sttree {
	return &Sttree{
		Root: SttNode{
			Addr:     0,
			Count:    0,
			Symbol:   "",
			Children: map[Addr]*SttNode{},
		},
	}
}

// AddStacktrace adds a stacktrace to the tree
func (t *Sttree) AddStacktrace(stt *Stt) {
	if len(stt.nodes) == 0 {
		return
	}

	t.Root.Count += stt.nodes[0].Count
	t.Root.addChildren(stt.nodes)
}

func (n *SttNode) addChildren(nodes []*SttNode) {
	if len(nodes) == 0 {
		return
	}

	node := nodes[0]
	addr := node.Addr
	child := n.Children[addr]
	if child == nil {
		n.Children[addr] = node
	} else {
		child.merge(node)
	}

	n.Children[addr].addChildren(nodes[1:])
}

func (n *SttNode) printNode(level int) {
	indentSpace := "    "
	indent := strings.Repeat(indentSpace, level)
	fmt.Printf("%s0x%x (%s) count:%d\n", indent, n.Addr, n.Symbol, n.Count)

	nchildren := len(n.Children)
	for _, child := range n.Children {
		child.printNode(level + 1)
	}

	// This is a leaf, so we also print label counters
	if nchildren == 0 {
		for lbl, lblCount := range n.Labels {
			fmt.Printf("%s%s%s count:%d\n", indent, indentSpace, lbl, lblCount)
		}
	}
}

// Print prints the tree
func (t *Sttree) Print() {
	t.Root.printNode(0)
}

func (n *SttNode) ToProtoNode() *tetragon.StackTraceNode {
	protoNode := tetragon.StackTraceNode{
		Address: &tetragon.StackAddress{Address: n.Addr, Symbol: n.Symbol},
		Count:   uint64(n.Count),
	}

	for lblKey, lblCount := range n.Labels {
		protoLabel := tetragon.StackTraceLabel{Key: lblKey, Count: uint64(lblCount)}
		protoNode.Labels = append(protoNode.Labels, &protoLabel)
	}

	for _, child := range n.Children {
		protoNode.Children = append(protoNode.Children, child.ToProtoNode())
	}

	return &protoNode
}
