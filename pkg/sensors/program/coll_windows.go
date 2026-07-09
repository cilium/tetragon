// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import "github.com/cilium/ebpf"

type LoadedMap struct {
	ID ebpf.MapID
}

type LoadedProgram struct {
	ID     ebpf.ProgramID
	MapIDs []ebpf.MapID
	Type   ebpf.ProgramType
}

type LoadedCollection struct {
	Programs map[string]*LoadedProgram
	Maps     map[string]*LoadedMap
}

func filterLoadedCollection(_ *LoadedCollection) *LoadedCollection {
	return nil
}

func printLoadedCollection(_ string, _ *LoadedCollection) {}
