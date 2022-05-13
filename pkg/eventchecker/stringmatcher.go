// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"fmt"
	"strings"
)

// StrMatch is an enum representing the kind of string matching we want to do
type StrMatch int

const (
	strFullMatch StrMatch = iota // NB: 0
	strPrefixMatch
	strSuffixMatch
	strContainsMatch
	strAlwaysMatch
)

// StringMatcher matches a string according to a StrMatch strategy
type StringMatcher struct {
	s string
	m StrMatch
}

// StringArg is a dummy interface for either a plain string (defaults to a full match) or
// a StringMatcher
type StringArg interface {
	// string -> FullMatch
	// StringMatcher
}

func stringMatcherFromArg(arg StringArg) StringMatcher {
	switch v := arg.(type) {
	case StringMatcher:
		return v
	case string:
		return FullStringMatch(v)
	}

	panic(fmt.Sprintf("stringMatcherFromArg: Unexpected type: %T", arg))
}

// FullStringMatch creates a new StringMatcher that matches a full string
func FullStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: strFullMatch}
}

// PrefixStringMatch creates a new StringMatcher that matches a prefix
func PrefixStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: strPrefixMatch}
}

// SuffixStringMatch creates a new StringMatcher that matches a suffix
func SuffixStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: strSuffixMatch}
}

// ContainsStringMatch creates a new StringMatcher that matches a substring
func ContainsStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: strContainsMatch}
}

// StringMatchAlways creates a new StringMatcher that always matches
func StringMatchAlways() StringMatcher {
	return StringMatcher{s: "", m: strAlwaysMatch}
}

// GetMatcher gets the matcher function for a StringMatcher
func (sm StringMatcher) GetMatcher() func(string) error {
	switch sm.m {
	case strFullMatch:
		return func(x string) error {
			if x == sm.s {
				return nil
			}
			return fmt.Errorf("'%s' does not match full string '%s'", x, sm.s)
		}
	case strPrefixMatch:
		return func(x string) error {
			if strings.HasPrefix(x, sm.s) {
				return nil
			}
			return fmt.Errorf("'%s' does not match prefix '%s'", x, sm.s)
		}
	case strSuffixMatch:
		return func(x string) error {
			if strings.HasSuffix(x, sm.s) {
				return nil
			}
			return fmt.Errorf("'%s' does not match suffix '%s'", x, sm.s)
		}
	case strContainsMatch:
		return func(x string) error {
			if strings.Contains(x, sm.s) {
				return nil
			}
			return fmt.Errorf("'%s' does not contain '%s'", x, sm.s)
		}
	case strAlwaysMatch:
		return func(x string) error {
			return nil
		}
	}
	return func(x string) error {
		return fmt.Errorf("internal error: Unknown matcher: %d", sm.m)
	}
}
