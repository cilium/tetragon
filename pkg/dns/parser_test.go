// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package dns

import (
	"bytes"
	"errors"
	"testing"
)

func buildQuery(t *testing.T, name string, qtype uint16, flags uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{0x12, 0x34, byte(flags >> 8), byte(flags), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if name != "" {
		for _, l := range bytes.Split([]byte(name), []byte{'.'}) {
			if len(l) > 63 {
				t.Fatalf("test bug: label too long: %q", l)
			}
			b.WriteByte(byte(len(l)))
			b.Write(l)
		}
	}
	b.WriteByte(0)
	b.Write([]byte{byte(qtype >> 8), byte(qtype)})
	b.Write([]byte{0x00, 0x01})
	return b.Bytes()
}

func TestParseStandardQueries(t *testing.T) {
	cases := []struct {
		name   string
		qname  string
		qtype  uint16
		flags  uint16
		expect string
		isResp bool
	}{
		{"A example.com", "example.com", 1, 0x0100, "example.com", false},
		{"AAAA example.com", "example.com", 28, 0x0100, "example.com", false},
		{"CNAME www.example.com", "www.example.com", 5, 0x0100, "www.example.com", false},
		{"PTR 1.in-addr.arpa", "1.in-addr.arpa", 12, 0x0100, "1.in-addr.arpa", false},
		{"response bit set", "x.test", 1, 0x8180, "x.test", true},
		{"uppercase lowercased", "WWW.EXAMPLE.COM", 1, 0x0100, "www.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse(buildQuery(t, c.qname, c.qtype, c.flags))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.QName != c.expect {
				t.Errorf("qname = %q, want %q", p.QName, c.expect)
			}
			if p.QType != c.qtype {
				t.Errorf("qtype = %d, want %d", p.QType, c.qtype)
			}
			if p.Response != c.isResp {
				t.Errorf("response = %v, want %v", p.Response, c.isResp)
			}
			if p.TxId != 0x1234 {
				t.Errorf("txid = %#x, want 0x1234", p.TxId)
			}
		})
	}
}

func TestParseMalformedRejected(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want error
	}{
		{"empty", []byte{}, ErrShort},
		{"header-with-qdcount-zero", make([]byte, 12), ErrNoQuestion},
		{"truncated-after-qdcount-one", []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, ErrShort},
		{"label-length-64", func() []byte {
			b := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
			b = append(b, 64)
			b = append(b, bytes.Repeat([]byte{'a'}, 64)...)
			b = append(b, 0, 0, 1, 0, 1)
			return b
		}(), ErrLabel},
		{"compression-in-question", func() []byte {
			b := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
			b = append(b, 0xc0, 0x0c, 0, 1, 0, 1)
			return b
		}(), ErrCompression},
		{"non-standard-opcode", func() []byte {
			b := []byte{0x00, 0x01, 0x08, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
			b = append(b, 1, 'a', 0, 0, 1, 0, 1)
			return b
		}(), ErrOpcode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.buf); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		buildQuery(&testing.T{}, "example.com", 1, 0x0100),
		buildQuery(&testing.T{}, "a", 28, 0x0100),
		{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1},
		make([]byte, 0),
		make([]byte, 4096),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Parse(b)
	})
}

func TestQTypeString(t *testing.T) {
	cases := map[uint16]string{
		1:    "A",
		5:    "CNAME",
		28:   "AAAA",
		257:  "CAA",
		9999: "TYPE9999",
	}
	for in, want := range cases {
		if got := QTypeString(in); got != want {
			t.Errorf("QTypeString(%d) = %q, want %q", in, got, want)
		}
	}
}
