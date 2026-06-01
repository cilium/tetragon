// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package cursorparser provides a small cursor-based helper for parsing short,
// delimiter-oriented strings.
//
// Use it when a grammar is simple enough to parse left-to-right but still needs
// to distinguish missing delimiters from trailing junk.
// It trims outer whitespace once, skips token-edge whitespace before Consume calls,
// and leaves text returned by ReadUntil and ReadRest for callers to validate.
//
// Examples of suitable inputs:
//   - assembly register dereferences such as "(%rsp)", "0x20(%rsp)", and
//     "0x20 ( %rsp )": read the offset until '(', consume '(', consume '%',
//     read the register until ')', consume ')', then require Done.
//   - register offsets such as "8%rsp" or "0x20 %rsp": read the offset until
//     '%', consume '%', then ReadRest for the register.
//   - prefixed tokens such as "%rax": consume '%', then ReadRest for the
//     payload.
//
// It is not a full expression parser; callers own token validation and numeric
// conversion after each cursor step.
package cursorparser

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type Parser struct {
	str string
	pos int
}

func New(str string) *Parser {
	return &Parser{str: strings.TrimSpace(str)}
}

func (p *Parser) skipSpace() {
	for p.pos < len(p.str) {
		r, size := utf8.DecodeRuneInString(p.str[p.pos:])
		if !unicode.IsSpace(r) {
			return
		}
		p.pos += size
	}
}

// Consume skips token-edge whitespace and consumes ch if it is next.
// The cursor advances only on a match, so callers can probe for
// delimiters without losing their position on failure.
func (p *Parser) Consume(ch byte) bool {
	p.skipSpace()
	if p.pos >= len(p.str) || p.str[p.pos] != ch {
		return false
	}
	p.pos++
	return true
}

// ReadUntil returns the text from the current cursor up to ch and
// leaves the cursor at ch.
func (p *Parser) ReadUntil(ch byte) (string, bool) {
	idx := strings.IndexByte(p.str[p.pos:], ch)
	if idx < 0 {
		return "", false
	}
	str := p.str[p.pos : p.pos+idx]
	p.pos += idx
	return str, true
}

// ReadRest returns the remaining expression text and moves the cursor
// to the end.
func (p *Parser) ReadRest() string {
	str := p.str[p.pos:]
	p.pos = len(p.str)
	return str
}

// Done reports whether only whitespace remains after the current cursor.
func (p *Parser) Done() bool {
	p.skipSpace()
	return p.pos == len(p.str)
}
