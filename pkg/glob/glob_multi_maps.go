// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package glob

import (
	"errors"
	"fmt"
	"slices"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	GlobPossibleMaxValues = 512 // this should match POSSIBLE_MAX_VALUES in bpf/glob/bpf_glob_multi.h
	GlobTableSize         = 256

	globTransitionBatchSize = 1024

	BitmapShift = 6
	BitmapMask  = 63
	BitsPerByte = 8
)

type Bitmap struct {
	V [GlobPossibleMaxValues / BitsPerByte / unsafe.Sizeof(uint64(0))]uint64 // one bit per state
}

func (b *Bitmap) Set(n int) {
	word := n >> BitmapShift
	position := n & BitmapMask
	b.V[word] |= uint64(1) << uint64(position)
}

type StateTransitions struct {
	Next [GlobTableSize]int32
}

func GetAll(start *DFAState, knownMap map[int]bool) ([]StateTransitions, map[int32][]int32) {
	visited := make(map[int]bool)
	queue := []*DFAState{start}
	visited[start.ID] = true

	isFinal := map[int32][]int32{}
	stateTransitions := []StateTransitions{}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for len(stateTransitions) <= curr.ID {
			stateTransitions = append(stateTransitions, StateTransitions{})
		}

		other, hasOther := curr.Transitions[Other]
		for char := range GlobTableSize {
			next, ok := curr.Transitions[char]
			if !ok && !knownMap[char] {
				next, ok = other, hasOther
			}
			if ok {
				// Zero means that no transition exists, so encode state IDs
				// starting at one.
				stateTransitions[curr.ID].Next[char] = int32(next.ID + 1)
			}
		}

		// we need to deduplicate curr.Matches here
		// this array should be already sorted here
		isFinal[int32(curr.ID)] = slices.Compact(curr.Matches)

		for _, next := range curr.Transitions {
			if !visited[next.ID] {
				visited[next.ID] = true
				queue = append(queue, next)
			}
		}
	}

	return stateTransitions, isFinal
}

type Data struct {
	finalStates      map[int32][]int32  // tg_glob_final
	stateTransitions []StateTransitions // tg_glob_dfa
}

func GenerateAndPopulateData(allPatterns map[string][]int32) Data {
	literals, knownMap := GetLiterals(allPatterns)
	nfa := BuildMultiNFA(allPatterns)
	dfa := ToDFA(nfa, literals)
	stateTransitions, finalStates := GetAll(dfa, knownMap)

	return Data{
		finalStates:      finalStates,
		stateTransitions: stateTransitions,
	}
}

func (g Data) GenerateFinalStatesMap(m *ebpf.Map) error {
	for c, f := range g.finalStates {
		if len(f) == 0 {
			continue
		}

		bitmap := Bitmap{}
		for _, b := range f {
			bitmap.Set(int(b))
		}

		if err := m.Update(c, bitmap, 0); err != nil {
			return fmt.Errorf("failed to insert bitmap: %w", err)
		}
	}
	return nil
}

func (g Data) GetFinalStatesMapSize() int {
	cnt := 0
	for _, f := range g.finalStates {
		if len(f) > 0 {
			cnt++
		}
	}
	if cnt == 0 {
		cnt++
	}
	return cnt
}

func (g Data) generateStateTransitionsMapSingle(m *ebpf.Map) error {
	for i, transitions := range g.stateTransitions {
		if err := m.Update(uint32(i), transitions, 0); err != nil {
			return fmt.Errorf("update state %d: %w", i, err)
		}
	}
	return nil
}

func (g Data) GenerateStateTransitionsMap(m *ebpf.Map) error {
	keys := make([]uint32, len(g.stateTransitions))
	for i := range keys {
		keys[i] = uint32(i)
	}

	for i := 0; i < len(g.stateTransitions); i += globTransitionBatchSize {
		beg := i
		end := min(beg+globTransitionBatchSize, len(keys))
		updated, err := m.BatchUpdate(keys[beg:end], g.stateTransitions[beg:end], nil)
		if errors.Is(err, ebpf.ErrNotSupported) {
			// batched update is not supported so try the single update
			return g.generateStateTransitionsMapSingle(m)
		}
		if err != nil {
			return fmt.Errorf("batch update states %d-%d: %w", beg, end-1, err)
		}
		if updated != end-beg {
			return fmt.Errorf("batch update states %d-%d: updated %d states", beg, end-1, updated)
		}
	}
	return nil
}

func (g Data) GetStateTransitionsMapSize() int {
	if len(g.stateTransitions) > 0 {
		return len(g.stateTransitions)
	}
	return 1
}
