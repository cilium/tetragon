/*
Open Source Initiative OSI - The MIT License (MIT):Licensing

The MIT License (MIT)
Copyright (c) 2013 - 2022 Ralph Caraveo (deckarep@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package mapset

import (
	"encoding/json"
	"fmt"
	"strings"
)

type threadUnsafeSet[T comparable] map[T]struct{}

// Assert concrete type:threadUnsafeSet adheres to Set interface.
var _ Set[string] = (*threadUnsafeSet[string])(nil)

func newThreadUnsafeSet[T comparable]() *threadUnsafeSet[T] {
	t := make(threadUnsafeSet[T])
	return &t
}

func newThreadUnsafeSetWithSize[T comparable](cardinality int) *threadUnsafeSet[T] {
	t := make(threadUnsafeSet[T], cardinality)
	return &t
}

func (s *threadUnsafeSet[T]) Add(v T) bool {
	prevLen := len(*s)
	s.add(v)
	return prevLen != len(*s)
}

// private version of Add which doesn't return a value
func (s *threadUnsafeSet[T]) add(v T) {
	(*s)[v] = struct{}{}
}

func (s *threadUnsafeSet[T]) Append(vs ...T) int {
	prevLen := len(*s)
	s.append(vs...)
	return len(*s) - prevLen
}

// private version of Append which doesn't return a value
func (s *threadUnsafeSet[T]) append(vs ...T) {
	for _, v := range vs {
		s.add(v)
	}
}

func (s *threadUnsafeSet[T]) AppendFrom(other Set[T]) int {
	o := other.(*threadUnsafeSet[T])

	prevLen := s.Cardinality()
	for elem := range *o {
		s.add(elem)
	}
	return s.Cardinality() - prevLen
}

func (s *threadUnsafeSet[T]) Cardinality() int {
	return len(*s)
}

func (s *threadUnsafeSet[T]) Clear() {
	// Constructions like this are optimised by compiler, and replaced by
	// mapclear() function, defined in
	// https://github.com/golang/go/blob/29bbca5c2c1ad41b2a9747890d183b6dd3a4ace4/src/runtime/map.go#L993)
	for key := range *s {
		delete(*s, key)
	}
}

func (s *threadUnsafeSet[T]) Clone() Set[T] {
	t := threadUnsafeSet[T](mapclone(*s))
	return &t
}

func (s *threadUnsafeSet[T]) Contains(v ...T) bool {
	for _, val := range v {
		if !s.contains(val) {
			return false
		}
	}
	return true
}

func (s *threadUnsafeSet[T]) ContainsOne(v T) bool {
	return s.contains(v)
}

func (s *threadUnsafeSet[T]) ContainsAny(v ...T) bool {
	for _, val := range v {
		if s.contains(val) {
			return true
		}
	}
	return false
}

func (s *threadUnsafeSet[T]) ContainsAnyElement(other Set[T]) bool {
	o := other.(*threadUnsafeSet[T])

	// loop over smaller set
	if s.Cardinality() < other.Cardinality() {
		for elem := range *s {
			if o.contains(elem) {
				return true
			}
		}
	} else {
		for elem := range *o {
			if s.contains(elem) {
				return true
			}
		}
	}
	return false
}

// private version of Contains for a single element v
func (s *threadUnsafeSet[T]) contains(v T) (ok bool) {
	_, found := (*s)[v]
	return found
}

func (s *threadUnsafeSet[T]) Difference(other Set[T]) Set[T] {
	o := other.(*threadUnsafeSet[T])

	diff := make(threadUnsafeSet[T], s.Cardinality())
	for elem := range *s {
		if !o.contains(elem) {
			diff.add(elem)
		}
	}
	return &diff
}

func (s *threadUnsafeSet[T]) Each(cb func(T) bool) {
	for elem := range *s {
		if cb(elem) {
			break
		}
	}
}

func (s *threadUnsafeSet[T]) Filter(cb func(T) bool) Set[T] {
	mappedSet := newThreadUnsafeSetWithSize[T](s.Cardinality())
	for elem := range *s {
		if cb(elem) {
			mappedSet.add(elem)
		}
	}
	return mappedSet
}

func (s *threadUnsafeSet[T]) Equal(other Set[T]) bool {
	o := other.(*threadUnsafeSet[T])

	if s.Cardinality() != other.Cardinality() {
		return false
	}
	for elem := range *s {
		if !o.contains(elem) {
			return false
		}
	}
	return true
}

func (s *threadUnsafeSet[T]) Intersect(other Set[T]) Set[T] {
	o := other.(*threadUnsafeSet[T])

	var intersection threadUnsafeSet[T]
	// loop over smaller set
	if s.Cardinality() < other.Cardinality() {
		intersection = make(threadUnsafeSet[T], s.Cardinality())
		for elem := range *s {
			if o.contains(elem) {
				intersection.add(elem)
			}
		}
	} else {
		intersection = make(threadUnsafeSet[T], o.Cardinality())
		for elem := range *o {
			if s.contains(elem) {
				intersection.add(elem)
			}
		}
	}
	return &intersection
}

func (s *threadUnsafeSet[T]) IsEmpty() bool {
	return len(*s) == 0
}

func (s *threadUnsafeSet[T]) IsProperSubset(other Set[T]) bool {
	return s.Cardinality() < other.Cardinality() && s.IsSubset(other)
}

func (s *threadUnsafeSet[T]) IsProperSuperset(other Set[T]) bool {
	return s.Cardinality() > other.Cardinality() && s.IsSuperset(other)
}

func (s *threadUnsafeSet[T]) IsSubset(other Set[T]) bool {
	o := other.(*threadUnsafeSet[T])
	if s.Cardinality() > other.Cardinality() {
		return false
	}
	for elem := range *s {
		if !o.contains(elem) {
			return false
		}
	}
	return true
}

func (s *threadUnsafeSet[T]) IsDisjoint(other Set[T]) bool {
	return !s.ContainsAnyElement(other)
}

func (s *threadUnsafeSet[T]) IsSuperset(other Set[T]) bool {
	return other.IsSubset(s)
}

func (s *threadUnsafeSet[T]) Iter() <-chan T {
	ch := make(chan T)
	go func() {
		for elem := range *s {
			ch <- elem
		}
		close(ch)
	}()

	return ch
}

func (s *threadUnsafeSet[T]) Iterator() *Iterator[T] {
	iterator, ch, stopCh := newIterator[T]()

	go func() {
	L:
		for elem := range *s {
			select {
			case <-stopCh:
				break L
			case ch <- elem:
			}
		}
		close(ch)
	}()

	return iterator
}

// Pop returns a popped item in case set is not empty, or nil-value of T
// if set is already empty
func (s *threadUnsafeSet[T]) Pop() (v T, ok bool) {
	for item := range *s {
		delete(*s, item)
		return item, true
	}
	return v, false
}

func (s *threadUnsafeSet[T]) PopN(n int) (items []T, count int) {
	if n <= 0 || len(*s) == 0 {
		return make([]T, 0), 0
	}
	sn := s.Cardinality()
	if n > sn {
		n = sn
	}

	items = make([]T, 0, sn)
	for item := range *s {
		if count >= n {
			break
		}
		delete(*s, item)
		items = append(items, item)
		count++
	}
	return items, count
}

func (s threadUnsafeSet[T]) Remove(v T) {
	delete(s, v)
}

func (s threadUnsafeSet[T]) RemoveAll(i ...T) {
	for _, elem := range i {
		delete(s, elem)
	}
}

func (s threadUnsafeSet[T]) String() string {
	items := make([]string, 0, len(s))

	for elem := range s {
		items = append(items, fmt.Sprintf("%v", elem))
	}
	return fmt.Sprintf("Set{%s}", strings.Join(items, ", "))
}

func (s *threadUnsafeSet[T]) SymmetricDifference(other Set[T]) Set[T] {
	o := other.(*threadUnsafeSet[T])

	// maximum number of elements is the sum of s and o cardinalities (when s and o are disjoint)
	n := s.Cardinality() + o.Cardinality()
	sd := make(threadUnsafeSet[T], n)
	for elem := range *s {
		if !o.contains(elem) {
			sd.add(elem)
		}
	}
	for elem := range *o {
		if !s.contains(elem) {
			sd.add(elem)
		}
	}
	return &sd
}

func (s threadUnsafeSet[T]) ToSlice() []T {
	keys := make([]T, 0, len(s))
	for elem := range s {
		keys = append(keys, elem)
	}

	return keys
}

func (s threadUnsafeSet[T]) Union(other Set[T]) Set[T] {
	o := other.(*threadUnsafeSet[T])

	// maximum number of elements is the sum of s and o cardinalities (when s and o are disjoint)
	n := s.Cardinality() + o.Cardinality()
	unionedSet := make(threadUnsafeSet[T], n)

	for elem := range s {
		unionedSet.add(elem)
	}
	for elem := range *o {
		unionedSet.add(elem)
	}
	return &unionedSet
}

// MarshalJSON creates a JSON array from the set, it marshals all elements
func (s threadUnsafeSet[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToSlice())
}

// UnmarshalJSON recreates a set from a JSON array, it only decodes
// primitive types. Numbers are decoded as json.Number.
func (s *threadUnsafeSet[T]) UnmarshalJSON(b []byte) error {
	var i []T
	err := json.Unmarshal(b, &i)
	if err != nil {
		return err
	}
	s.append(i...)

	return nil
}
