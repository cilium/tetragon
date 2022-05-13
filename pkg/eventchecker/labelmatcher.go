// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

// LabelMatch matches key, value pairs on labels
type LabelMatch struct {
	Key string
	Val StringMatcher
}

// LabelMatchVal constructs a new LabelMatch that matches over full values
func LabelMatchVal(key string, val string) LabelMatch {
	return LabelMatch{
		Key: key,
		Val: FullStringMatch(val),
	}
}

// LabelMatchValPrefix constructs a new LabelMatch that matches over value prefixes
func LabelMatchValPrefix(key string, valPrefix string) LabelMatch {
	return LabelMatch{
		Key: key,
		Val: PrefixStringMatch(valPrefix),
	}
}
