// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package glob

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGlobFSM(t *testing.T) {
	for _, c := range GlobTestCases {
		allPatterns := map[string][]int32{
			c.Pattern: {1},
		}
		literals, knownMap := GetLiterals(allPatterns)
		nfa := BuildMultiNFA(allPatterns)
		dfa := ToDFA(nfa, literals)
		res := MatchString(dfa, c.Path, knownMap)
		if c.Match {
			assert.ElementsMatch(t, []int32{1}, res, "pattern: %s input: %s", c.Pattern, c.Path)
		} else {
			assert.Empty(t, res, "pattern: %s input: %s", c.Pattern, c.Path)
		}
	}
}

func TestGlobFSMMulti(t *testing.T) {
	for _, c := range GlobTestCasesMulti {
		literals, knownMap := GetLiterals(c.Patterns)
		nfa := BuildMultiNFA(c.Patterns)
		dfa := ToDFA(nfa, literals)
		for _, ts := range c.Tests {
			assert.ElementsMatch(t, ts.Values, MatchString(dfa, ts.Path, knownMap))
		}
	}
}

func FuzzGlobGetLiterals(f *testing.F) {
	for _, c := range GlobTestCases {
		f.Add(c.Pattern)
	}
	f.Fuzz(func(_ *testing.T, pattern string) {
		allPatterns := map[string][]int32{
			pattern: {1},
		}
		GetLiterals(allPatterns)
	})
}

func FuzzGlobBuildMultiNFA(f *testing.F) {
	for _, c := range GlobTestCases {
		f.Add(c.Pattern)
	}
	f.Fuzz(func(_ *testing.T, pattern string) {
		allPatterns := map[string][]int32{
			pattern: {1},
		}
		BuildMultiNFA(allPatterns)
	})
}
