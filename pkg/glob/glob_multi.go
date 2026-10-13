// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package glob

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	TypeEpsilon = iota
	TypeLiteral
	TypeAny   // ?
	TypeClass // [abc] or [!abc]
)

// Helper for "Other" transitions in DFA
const Other = -999

type State struct {
	ID       int
	Type     int
	Char     rune
	Class    map[rune]bool
	NotClass bool
	Out      *State
	Out1     *State
	MatchID  []int32
}

type NFA struct {
	Start     *State
	NumStates int
}

type DFAState struct {
	ID          int
	Transitions map[int]*DFAState
	Matches     []int32
}

// --- Parser ---
type parserCtx struct {
	pattern string
	pos     int
}

func (p *parserCtx) current() rune {
	if p.pos >= len(p.pattern) {
		return 0
	}
	return rune(p.pattern[p.pos])
}

func (p *parserCtx) advance() { p.pos++ }

func buildFrag(ctx *parserCtx) (*State, *State) {
	start := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
	end := start

	for ctx.pos < len(ctx.pattern) {
		char := ctx.current()

		if char == '}' || char == ',' {
			break
		}

		newState := &State{MatchID: []int32{-1}}

		switch char {
		case '?':
			newState.Type = TypeAny
			end.Out = newState
			end = newState
			ctx.advance()

		case '*':
			hub := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			end.Out = hub
			loopStep := &State{Type: TypeAny, MatchID: []int32{-1}}
			hub.Out = loopStep
			loopStep.Out = hub
			hub.Out1 = newState
			end = newState
			ctx.advance()

		case '[':
			ctx.advance()
			negate := false
			if ctx.current() == '!' {
				negate = true
				ctx.advance()
			}

			charSet := make(map[rune]bool)
			var prevChar rune = -1 // Track previous char for range detection

			for ctx.pos < len(ctx.pattern) && ctx.current() != ']' {
				curr := ctx.current()

				// Check for Range: we see a hyphen, we have a previous char,
				// and the NEXT char is not the closing bracket.
				isRange := false
				if curr == '-' && prevChar != -1 {
					// Peek ahead
					nextPos := ctx.pos + 1
					if nextPos < len(ctx.pattern) && rune(ctx.pattern[nextPos]) != ']' {
						isRange = true
						ctx.advance() // Consume '-'
						rangeEnd := ctx.current()

						// Add all characters in range
						for r := prevChar + 1; r <= rangeEnd; r++ {
							charSet[r] = true
						}
						// The 'rangeEnd' itself will be added by the standard logic below
						// or we can consume it here. Let's consume it here to allow "a-c-e" logic if needed,
						// but simpler is to set curr = rangeEnd and let loop finish.
						curr = rangeEnd
						prevChar = -1 // Reset prev so we don't chain ranges incorrectly immediately
					}
				}

				if !isRange {
					charSet[curr] = true
					prevChar = curr
				}
				ctx.advance()
			}
			if ctx.current() == ']' {
				ctx.advance()
			}

			newState.Type = TypeClass
			newState.Class = charSet
			newState.NotClass = negate
			end.Out = newState
			end = newState

		case '{':
			ctx.advance()
			splitStart := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			splitEnd := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			end.Out = splitStart

			for {
				subStart, subEnd := buildFrag(ctx)
				if splitStart.Out == nil {
					splitStart.Out = subStart
				} else if splitStart.Out1 == nil {
					splitStart.Out1 = subStart
				} else {
					newSplit := &State{Type: TypeEpsilon, Out: subStart, Out1: splitStart.Out1, MatchID: []int32{-1}}
					splitStart.Out1 = newSplit
				}
				subEnd.Out = splitEnd

				if ctx.current() == '}' {
					ctx.advance()
					break
				} else if ctx.current() == ',' {
					ctx.advance()
				} else {
					break
				}
			}
			end = splitEnd

		default:
			newState.Type = TypeLiteral
			newState.Char = char
			end.Out = newState
			end = newState
			ctx.advance()
		}
	}
	return start, end
}

func buildPatternNFA(pattern string, id []int32) (*State, *State) {
	ctx := &parserCtx{pattern: pattern, pos: 0}
	start, end := buildFrag(ctx)
	// Create explicit success state
	success := &State{Type: TypeEpsilon, MatchID: id}
	end.Out = success
	return start, success
}

func BuildMultiNFA(patterns map[string][]int32) *NFA {
	globalStart := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
	curr := globalStart
	idx := 0
	for p, i := range patterns {
		pStart, _ := buildPatternNFA(p, i)
		curr.Out = pStart
		if idx < len(patterns)-1 {
			next := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			curr.Out1 = next
			curr = next
		}
		idx++
	}
	numStates := assignIDs(globalStart)
	return &NFA{
		Start:     globalStart,
		NumStates: numStates,
	}
}

func matches(s *State, char int) bool {
	r := rune(char)
	switch s.Type {
	case TypeLiteral:
		return s.Char == r
	case TypeAny:
		return true
	case TypeClass:
		_, found := s.Class[r]
		if s.NotClass {
			return !found
		}
		return found
	}
	return false
}

func GetLiterals(patterns map[string][]int32) ([]int, map[int]bool) {
	seen := make(map[rune]bool)
	literals := []int{}
	knownMap := make(map[int]bool)

	add := func(r rune) {
		if !seen[r] {
			seen[r] = true
			literals = append(literals, int(r))
			knownMap[int(r)] = true
		}
	}

	for p := range patterns {
		var prevChar rune = -1
		inBracket := false

		for i := range len(p) {
			c := rune(p[i])

			if c == '[' {
				inBracket = true
				prevChar = -1
				continue
			}
			if c == ']' {
				inBracket = false
				prevChar = -1
				continue
			}

			if inBracket {
				// Handle negation '!' skipping
				if c == '!' && i > 0 && p[i-1] == '[' {
					continue
				}

				// Check for Range Detection similar to Parser
				if c == '-' && prevChar != -1 {
					// Check lookahead
					if i+1 < len(p) && p[i+1] != ']' {
						rangeEnd := rune(p[i+1])
						// Expand range
						for k := prevChar + 1; k < rangeEnd; k++ {
							add(k)
						}
						// We don't add '-' as a literal here if it's acting as an operator
						continue
					}
				}
				add(c)
				prevChar = c
			} else {
				// Outside brackets
				if !strings.ContainsRune("*?{},", c) {
					add(c)
				}
			}
		}
	}
	return literals, knownMap
}

func ToDFA(nfa *NFA, literals []int) *DFAState {
	alphabet := append(literals, Other)

	startClosure, startKey := epsilonClosure([]*State{nfa.Start}, nfa.NumStates)
	startDFA := &DFAState{ID: 0, Transitions: make(map[int]*DFAState)}
	startDFA.Matches = getMatches(startClosure)

	knownStates := map[string]*DFAState{startKey: startDFA}
	queue := []*DFAState{startDFA}
	stateSets := [][]*State{startClosure}
	idCounter := 1

	for queueIndex := 0; queueIndex < len(queue); queueIndex++ {
		currDFA := queue[queueIndex]
		currNFAStates := stateSets[currDFA.ID]

		for _, inputChar := range alphabet {
			moveSet := []*State{}

			for _, s := range currNFAStates {
				isMatch := false
				if inputChar == Other {
					// Other matches if the state accepts things NOT in our literal list
					if s.Type == TypeAny {
						isMatch = true
					} else if s.Type == TypeClass && s.NotClass {
						isMatch = true
					}
				} else {
					isMatch = matches(s, inputChar)
				}

				if isMatch {
					if s.Out != nil {
						moveSet = append(moveSet, s.Out)
					}
					if s.Out1 != nil {
						moveSet = append(moveSet, s.Out1)
					}
				}
			}

			if len(moveSet) == 0 {
				continue
			}

			closure, key := epsilonClosure(moveSet, nfa.NumStates)

			if target, exists := knownStates[key]; exists {
				currDFA.Transitions[inputChar] = target
			} else {
				newDFA := &DFAState{ID: idCounter, Transitions: make(map[int]*DFAState)}
				idCounter++
				newDFA.Matches = getMatches(closure)

				knownStates[key] = newDFA
				stateSets = append(stateSets, closure)
				currDFA.Transitions[inputChar] = newDFA
				queue = append(queue, newDFA)
			}
		}
	}
	return startDFA
}

func assignIDs(start *State) int {
	visited := make(map[*State]bool)
	id := 0
	var dfs func(*State)
	dfs = func(s *State) {
		if s == nil || visited[s] {
			return
		}
		visited[s] = true
		s.ID = id
		id++
		dfs(s.Out)
		dfs(s.Out1)
	}
	dfs(start)
	return id
}

func epsilonClosure(states []*State, numStates int) ([]*State, string) {
	closure := make([]*State, 0, len(states))
	stateSet := make([]byte, (numStates+7)/8)

	add := func(s *State) {
		word := s.ID / 8
		mask := byte(1 << (s.ID % 8))
		if stateSet[word]&mask == 0 {
			stateSet[word] |= mask
			closure = append(closure, s)
		}
	}

	for _, s := range states {
		add(s)
	}

	// Recheck the length because add can extend closure during traversal.
	i := 0
	for i < len(closure) {
		s := closure[i]
		i++
		if s.Type == TypeEpsilon {
			if s.Out != nil {
				add(s.Out)
			}
			if s.Out1 != nil {
				add(s.Out1)
			}
		}
	}

	return closure, string(stateSet)
}

func getMatches(states []*State) []int32 {
	matches := []int32{}
	seen := make(map[int32]bool)
	for _, s := range states {
		for _, matchID := range s.MatchID {
			if matchID != -1 && !seen[matchID] {
				matches = append(matches, matchID)
				seen[matchID] = true
			}
		}
	}
	slices.Sort(matches)
	return matches
}

func MatchString(dfa *DFAState, input string, knownLiterals map[int]bool) []int32 {
	current := dfa
	for _, char := range input {
		c := int(char)

		// 1. Try Specific Transition
		next, exists := current.Transitions[c]

		if !exists {
			// 2. If NOT exists, we check if this char is "Known"
			if knownLiterals[c] {
				// It IS a known literal (like 'b' in [!b]), but had no transition.
				// This means it failed the check. We must NOT use "Other".
				return nil
			}

			// 3. If it is Unknown (like 'z'), use Other fallback
			next, exists = current.Transitions[Other]
		}

		if !exists {
			return nil
		}
		current = next
	}
	return current.Matches
}

func ExportToDOT(w io.Writer, start *DFAState) error {
	// Helper function to handle writing and error checking
	writeLine := func(s string) error {
		_, err := fmt.Fprintln(w, s)
		return err
	}

	if err := writeLine("digraph DFA {"); err != nil {
		return err
	}
	if err := writeLine("  rankdir=LR;"); err != nil {
		return err
	}
	if err := writeLine("  node [shape = circle];"); err != nil {
		return err
	}

	visited := make(map[int]bool)
	queue := []*DFAState{start}
	visited[start.ID] = true

	// Buffers to ensure we print nodes before edges
	nodeDefs := []string{}
	edges := []string{}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		// 1. Define Node Visuals
		label := strconv.Itoa(curr.ID)
		shape := "circle"

		if len(curr.Matches) > 0 {
			shape = "doublecircle" // Standard for accepting states
			// Show which patterns matched
			label += fmt.Sprintf("\nMatch: %v", curr.Matches)
		}
		nodeDefs = append(nodeDefs, fmt.Sprintf("  %d [label=\"%s\", shape=%s];", curr.ID, label, shape))

		// 2. Process Transitions (Grouped for cleaner graphs)
		// We group transitions: if 'a', 'b', and 'c' all go to State 5, we draw one arrow labeled "a,b,c"
		grouped := make(map[int][]string)

		for char, next := range curr.Transitions {
			charLabel := ""
			if char == Other {
				charLabel = "OTHER"
			} else {
				charLabel = string(rune(char))
			}
			grouped[next.ID] = append(grouped[next.ID], charLabel)

			if !visited[next.ID] {
				visited[next.ID] = true
				queue = append(queue, next)
			}
		}

		for destID, labels := range grouped {
			sort.Strings(labels)
			edgeLabel := strings.Join(labels, ",")
			// If too long, truncate for display
			if len(edgeLabel) > 15 {
				edgeLabel = edgeLabel[:12] + "..."
			}
			edges = append(edges, fmt.Sprintf("  %d -> %d [label=\"%s\"];", curr.ID, destID, edgeLabel))
		}
	}

	// Print Node Definitions
	for _, n := range nodeDefs {
		if err := writeLine(n); err != nil {
			return err
		}
	}

	// Print Edges
	for _, e := range edges {
		if err := writeLine(e); err != nil {
			return err
		}
	}

	if err := writeLine("}"); err != nil {
		return err
	}

	return nil
}
