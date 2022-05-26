package program

import "fmt"

// State represents the state of a BPF program or map.
//
// NB: Currently there is no case where we attempt to load a program that is
// already loaded. If this changes, we can use the count as a reference count
// to track users of a bpf program.
type State struct {
	//   0: idle (not loaded)
	//   >=1: loaded, with N references
	//  -1: disabled
	count int
}

func Idle() State {
	return State{0}
}

func (s *State) IsLoaded() bool {
	return s.count > 0
}

func (s State) IsDisabled() bool {
	return s.count == -1
}

func (s *State) SetDisabled() {
	if s.IsLoaded() {
		panic(fmt.Errorf("called SetDisabled() while program is loaded (cnt: %d)", s.count))
	}
	s.count = -1
}

func (s *State) RefInc() {
	if s.IsDisabled() {
		panic(fmt.Errorf("called RefInc() while program is disabled (cnt: %d)", s.count))
	}
	s.count++
}

func (s *State) RefDec() int {
	if s.IsDisabled() {
		panic(fmt.Errorf("called RefDec() while program is disabled (cnt: %d)", s.count))
	}
	s.count--
	return s.count
}
