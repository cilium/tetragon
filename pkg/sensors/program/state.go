package program

// State represents the state of a BPF program or map.
//
// NB: Currently there is no case where we attempt to load a program that is
// already loaded. If this changes, we can use the count as a reference count
// to track users of a bpf program.
type State struct {
	//   0: idle (not loaded)
	//   >=1: loaded, with N references
	count int
}

func Idle() State {
	return State{0}
}

func (s *State) IsLoaded() bool {
	return s.count > 0
}

func (s *State) RefInc() {
	s.count++
}

func (s *State) RefDec() int {
	s.count--
	return s.count
}
