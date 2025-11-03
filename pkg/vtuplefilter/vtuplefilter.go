// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package vtuplefilter

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/vtuple"
)

type Port = uint16
type Addr = net.IP

type ParseError struct {
	msg string
}

func (e *ParseError) Error() string {
	return "parsing error: " + e.msg
}

func ParseErrorFmt(s string, args ...interface{}) *ParseError {
	return &ParseError{
		msg: fmt.Sprintf(s, args...),
	}
}

// FromLine
func FromLine(s string) (Filter, error) {
	var fs []Filter

	for ss := range strings.SplitSeq(s, ",") {
		var f Filter
		opts := strings.Split(ss, "=")
		if len(opts) != 2 {
			return nil, ParseErrorFmt("expecting x=a format for %s", ss)
		}

		switch opts[0] {
		case "sport", "dport", "port":
			port64, err := strconv.ParseUint(opts[1], 10, 16)
			if err != nil {
				return nil, ParseErrorFmt("failed to parse %s as port: %s", opts[1], err)
			}
			port16 := uint16(port64)
			switch opts[0] {
			case "sport":
				f = CreateSrcPortFilter(port16)
			case "dport":
				f = CreateDstPortFilter(port16)
			case "port":
				f = CreateAnyPortFilter(port16)
			}

		case "saddr":
		case "daddr":
		case "addr":
			ip := net.ParseIP(opts[1])
			if ip == nil {
				return nil, ParseErrorFmt("failed to parse %s as ip", opts[1])
			}

			switch opts[0] {
			case "saddr":
				f = CreateSrcAddrFilter(ip)
			case "daddr":
				f = CreateDstAddrFilter(ip)
			case "addr":
				f = CreateAnyAddrFilter(ip)
			}

		case "prot":
			switch strings.ToLower(opts[1]) {
			case "tcp":
				f = &ProtTcpFilter{}
			case "udp":
				f = &ProtUdpFilter{}

				// NB: once needed, we can easily do {tcp,udp}{4,6}
			}

		default:
			return nil, ParseErrorFmt("cannot parse %s: unknown %s", ss, opts[0])
		}

		if f == nil {
			panic("Unexpected error: f should be set")
		}
		fs = append(fs, f)
	}

	return &And{fs: fs}, nil
}

type Filter interface {
	FilterFn(t vtuple.VTuple) bool
}

// Logical operations
type And struct {
	fs []Filter
}

func (op *And) FilterFn(t vtuple.VTuple) bool {
	for _, f := range op.fs {
		if !f.FilterFn(t) {
			return false
		}
	} // NB: for 0 filters, AND returns true
	return true
}

func CreateAndFilter(fs ...Filter) Filter {
	return &And{fs: fs}
}

type Or struct {
	fs []Filter
}

func (op *Or) FilterFn(t vtuple.VTuple) bool {
	for _, f := range op.fs {
		if f.FilterFn(t) {
			return true
		}
	}
	// NB: for 0 filters, OR returns false
	return false
}

func CreateOrFilter(fs ...Filter) Filter {
	return &Or{fs: fs}
}

type Not struct {
	f Filter
}

func (op *Not) FilterFn(t vtuple.VTuple) bool {
	return !op.f.FilterFn(t)
}

// getters/setters (or projections if you are into SQL)

type PortFilter struct {
	getPort (func(vtuple.VTuple) Port)
	pred    (func(Port) bool)
}

// port filters

func (pf *PortFilter) FilterFn(t vtuple.VTuple) bool {
	addr := pf.getPort(t)
	return pf.pred(addr)
}

func CreateSrcPortFilter(port Port) Filter {
	return &PortFilter{
		getPort: func(t vtuple.VTuple) Port { return t.SrcPort() },
		pred:    func(p Port) bool { return p == port },
	}
}
func CreateDstPortFilter(port Port) Filter {
	return &PortFilter{
		getPort: func(t vtuple.VTuple) Port { return t.DstPort() },
		pred:    func(p Port) bool { return p == port },
	}
}

func CreateAnyPortFilter(port Port) Filter {
	srcF := CreateSrcPortFilter(port)
	dstF := CreateDstPortFilter(port)
	return CreateOrFilter(srcF, dstF)
}

// address filters

type AddrFilter struct {
	getAddr (func(vtuple.VTuple) Addr)
	pred    (func(Addr) bool)
}

func (pf *AddrFilter) FilterFn(t vtuple.VTuple) bool {
	addr := pf.getAddr(t)
	return pf.pred(addr)
}

func CreateSrcAddrFilter(addr Addr) Filter {
	return &AddrFilter{
		getAddr: func(t vtuple.VTuple) Addr { return t.SrcAddr() },
		pred:    func(a Addr) bool { return a.Equal(addr) },
	}
}

func CreateDstAddrFilter(addr Addr) Filter {
	return &AddrFilter{
		getAddr: func(t vtuple.VTuple) Addr { return t.DstAddr() },
		pred:    func(a Addr) bool { return a.Equal(addr) },
	}
}

func CreateAnyAddrFilter(addr Addr) Filter {
	srcF := CreateSrcAddrFilter(addr)
	dstF := CreateDstAddrFilter(addr)
	return CreateOrFilter(srcF, dstF)
}

// protocol filters

type ProtTcpFilter struct{}

func (f *ProtTcpFilter) FilterFn(t vtuple.VTuple) bool {
	return t.IsTCP()
}

type ProtUdpFilter struct{}

func (f *ProtUdpFilter) FilterFn(t vtuple.VTuple) bool {
	return t.IsUDP()
}

type ProtIP4Filter struct{}

func (f *ProtIP4Filter) FilterFn(t vtuple.VTuple) bool {
	return t.IsIP4()
}

type ProtIP6Filter struct{}

func (f *ProtIP6Filter) FilterFn(t vtuple.VTuple) bool {
	return t.IsIP6()
}
