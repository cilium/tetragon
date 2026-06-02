// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <yara.h>

// rule_identifier is a union accessor function.
// (CGO does not represent them properly to Go code.)
static const char* rule_identifier(YR_RULE* r) {
	return r->identifier;
}

// rule_namespace is a union accessor function.
// (CGO does not represent them properly to Go code.)
static const char* rule_namespace(YR_RULE* r) {
	return r->ns->name;
}

// rule_tags returns pointers to the tag names associated with a rule,
// using YARA's own implementation.
static void rule_tags(YR_RULE* r, const char *tags[], int *n) {
	const char *tag;
	int i = 0;
	yr_rule_tags_foreach(r, tag) {
		if (i < *n)
			tags[i] = tag;
		i++;
	};
	*n = i;
	return;
}

// rule_tags returns pointers to the meta variables associated with a
// rule, using YARA's own implementation.
static void rule_metas(YR_RULE* r, const YR_META *metas[], int *n) {
	const YR_META *meta;
	int i = 0;
	yr_rule_metas_foreach(r, meta) {
		if (i < *n)
			metas[i] = meta;
		i++;
	};
	*n = i;
	return;
}

// meta_get is a union accessor function.
// (CGO does not represent them properly to Go code.)
static void meta_get(YR_META *m, const char** identifier, char** string) {
	*identifier = m->identifier;
	*string = (char*)m->string;
	return;
}

// rule_strings returns pointers to the matching strings associated
// with a rule, using YARA's macro-based implementation.
static void rule_strings(YR_RULE* r, const YR_STRING *strings[], int *n) {
	const YR_STRING *string;
	int i = 0;
	yr_rule_strings_foreach(r, string) {
		if (i < *n)
			strings[i] = string;
		i++;
	}
	*n = i;
	return;
}

// string_identifier is a union accessor function.
// (CGO does not represent them properly to Go code.)
static const char* string_identifier(YR_STRING* s) {
	return s->identifier;
}

// string_matches returns pointers to the string match objects
// associated with a string, using YARA's macro-based implementation.
static void string_matches(YR_SCAN_CONTEXT *ctx, YR_STRING* s, const YR_MATCH *matches[], int *n) {
	const YR_MATCH *match;
	int i = 0;
	yr_string_matches_foreach(ctx, s, match) {
		if (i < *n)
			matches[i] = match;
		i++;
	};
	*n = i;
	return;
}

// get_rules returns pointers to the RULE objects for a ruleset, using
// YARA's macro-based implementation.
static void get_rules(YR_RULES *ruleset, const YR_RULE *rules[], int *n) {
	const YR_RULE *rule;
	int i = 0;
	yr_rules_foreach(ruleset, rule) {
		if (i < *n)
			rules[i] = rule;
		i++;
	}
	*n = i;
	return;
}

*/
import "C"
import (
	"runtime"
	"unsafe"
)

// Rule represents a single rule as part of a ruleset.
type Rule struct {
	cptr *C.YR_RULE
	// Save underlying YR_RULES / YR_COMPILER from being discarded through GC
	owner interface{}
}

// Identifier returns the rule's name.
func (r *Rule) Identifier() string {
	id := C.GoString(C.rule_identifier(r.cptr))
	runtime.KeepAlive(r)
	return id
}

// Namespace returns the rule's namespace.
func (r *Rule) Namespace() string {
	namespace := C.GoString(C.rule_namespace(r.cptr))
	runtime.KeepAlive(r)
	return namespace
}

// Tags returns the rule's tags.
func (r *Rule) Tags() (tags []string) {
	var size C.int
	C.rule_tags(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	tagptrs := make([]*C.char, int(size))
	C.rule_tags(r.cptr, &tagptrs[0], &size)
	for _, t := range tagptrs {
		tags = append(tags, C.GoString(t))
	}
	runtime.KeepAlive(r)
	return
}

// Meta represents a rule meta variable. Value can be of type string,
// int, boolean, or nil.
type Meta struct {
	Identifier string
	Value      interface{}
}

// Metas returns the rule's meta variables as a list of Meta
// objects.
func (r *Rule) Metas() (metas []Meta) {
	var size C.int
	C.rule_metas(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	mptrs := make([]*C.YR_META, int(size))
	C.rule_metas(r.cptr, &mptrs[0], &size)
	for _, cptr := range mptrs {
		var cid, cstr *C.char
		C.meta_get(cptr, &cid, &cstr)
		id := C.GoString(cid)
		var val interface{}
		switch cptr._type {
		case C.META_TYPE_STRING:
			val = C.GoString(cstr)
		case C.META_TYPE_INTEGER:
			val = int(cptr.integer)
		case C.META_TYPE_BOOLEAN:
			val = (cptr.integer != 0)
		}
		metas = append(metas, Meta{id, val})
	}
	runtime.KeepAlive(r)
	return
}

// IsPrivate returns true if the rule is marked as private.
func (r *Rule) IsPrivate() bool {
	private := r.cptr.flags&C.RULE_FLAGS_PRIVATE != 0
	runtime.KeepAlive(r)
	return private
}

// IsGlobal returns true if the rule is marked as global.
func (r *Rule) IsGlobal() bool {
	global := r.cptr.flags&C.RULE_FLAGS_GLOBAL != 0
	runtime.KeepAlive(r)
	return global
}

// String represents a string as part of a rule.
type String struct {
	cptr *C.YR_STRING
	// Save underlying YR_RULES / YR_COMPILER from being discarded through GC
	owner interface{}
}

// Strings returns the rule's strings.
func (r *Rule) Strings() (strs []String) {
	var size C.int
	C.rule_strings(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	ptrs := make([]*C.YR_STRING, int(size))
	C.rule_strings(r.cptr, &ptrs[0], &size)
	for _, ptr := range ptrs {
		strs = append(strs, String{ptr, r.owner})
	}
	return
}

// Identifier returns the string's name.
func (s *String) Identifier() string {
	id := C.GoString(C.string_identifier(s.cptr))
	runtime.KeepAlive(s)
	return id
}

// Match represents a string match.
type Match struct {
	cptr *C.YR_MATCH
	// Save underlying YR_RULES from being discarded through GC
	owner interface{}
}

// Matches returns all matches that have been recorded for the string.
func (s *String) Matches(sc *ScanContext) (matches []Match) {
	if sc == nil || sc.cptr == nil {
		return
	}
	var size C.int
	C.string_matches(sc.cptr, s.cptr, nil, &size)
	ptrs := make([]*C.YR_MATCH, int(size))
	if size == 0 {
		return
	}
	C.string_matches(sc.cptr, s.cptr, &ptrs[0], &size)
	for _, ptr := range ptrs {
		matches = append(matches, Match{ptr, s.owner})
	}
	return
}

// Base returns the base offset of the memory block in which the
// string match occurred.
func (m *Match) Base() int64 {
	base := int64(m.cptr.base)
	runtime.KeepAlive(m)
	return base
}

// Offset returns the offset at which the string match occurred.
func (m *Match) Offset() int64 {
	offset := int64(m.cptr.offset)
	runtime.KeepAlive(m)
	return offset
}

// XorKey returns the XOR value with which the string match occurred.
// Note: xor_key field was added in YARA 4.3; returns 0 on older versions.
func (m *Match) XorKey() uint8 {
	return 0
}

// Data returns the blob of data associated with the string match.
func (m *Match) Data() []byte {
	data := C.GoBytes(unsafe.Pointer(m.cptr.data), C.int(m.cptr.data_length))
	runtime.KeepAlive(m)
	return data
}

func (r *Rule) getMatchStrings(sc *ScanContext) (matchstrings []MatchString) {
	for _, s := range r.Strings() {
		for _, m := range s.Matches(sc) {
			matchstrings = append(matchstrings, MatchString{
				Name:   s.Identifier(),
				Base:   uint64(m.Base()),
				Offset: uint64(m.Offset()),
				Data:   m.Data(),
				XorKey: m.XorKey(),
			})
		}
	}
	return
}

// Enable enables a single rule.
func (r *Rule) Enable() {
	C.yr_rule_enable(r.cptr)
	runtime.KeepAlive(r)
}

// Disable disables a single rule.
func (r *Rule) Disable() {
	C.yr_rule_disable(r.cptr)
	runtime.KeepAlive(r)
}

// GetRules returns a slice of rule objects that are part of the
// ruleset.
func (r *Rules) GetRules() (rules []Rule) {
	var size C.int
	C.get_rules(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	ptrs := make([]*C.YR_RULE, int(size))
	C.get_rules(r.cptr, &ptrs[0], &size)
	for _, ptr := range ptrs {
		rules = append(rules, Rule{ptr, r})
	}
	return
}
