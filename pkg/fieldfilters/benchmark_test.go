// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"flag"
	"io"
	"math/rand"
	"os"
	"testing"

	"github.com/sryoya/protorand"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/encoder"
)

var Seed int64

func TestMain(m *testing.M) {
	flag.Int64Var(&Seed, "seed", -1, "seed for event generation, negative for random")
	flag.Parse()
	if Seed < 0 {
		Seed = rand.Int63()
	}

	code := m.Run()
	os.Exit(code)
}

type randomEventGenerator struct {
	pr *protorand.ProtoRand
	in *tetragon.GetEventsResponse
}

func (gen *randomEventGenerator) Generate(tb testing.TB) *tetragon.GetEventsResponse {
	msg, err := gen.pr.Gen(gen.in)
	require.NoError(tb, err, "failed to generate random message")
	return msg.ProtoReflect().Interface().(*tetragon.GetEventsResponse)
}

func (gen *randomEventGenerator) GenerateN(b *testing.B) []*tetragon.GetEventsResponse {
	evs := make([]*tetragon.GetEventsResponse, b.N)
	for i := range b.N {
		ev := gen.Generate(b)
		evs[i] = ev
	}
	return evs
}

func newRandomEventGenerator(tb testing.TB, seed int64) *randomEventGenerator {
	tb.Logf("configured random event generator (seed=%d)", seed)
	pr := protorand.New()
	pr.Seed(seed)
	return &randomEventGenerator{
		pr: pr,
		in: &tetragon.GetEventsResponse{},
	}
}

func getEncoder() encoder.EventEncoder {
	w := io.Discard
	return encoder.NewProtojsonEncoder(w)
}

// The base case where we just serialize an event without any filtering.
func BenchmarkSerialize(b *testing.B) {
	b.StopTimer()
	gen := newRandomEventGenerator(b, Seed)
	encoder := getEncoder()
	evs := gen.GenerateN(b)
	b.StartTimer()

	for i := range b.N {
		ev := evs[i]
		err := encoder.Encode(ev)
		require.NoError(b, err, "event must encode")
	}
}

// A significant portion of the overhead of the current field filters implementation comes
// from doing a deep copy on the event. Measure that here.
func BenchmarkSerialize_DeepCopy(b *testing.B) {
	b.StopTimer()
	gen := newRandomEventGenerator(b, Seed)
	encoder := getEncoder()
	evs := gen.GenerateN(b)
	b.StartTimer()

	for i := range b.N {
		ev := evs[i]
		ev = proto.Clone(ev).(*tetragon.GetEventsResponse)
		err := encoder.Encode(ev)
		require.NoError(b, err, "event must encode")
	}
}

// Do a deep copy of just the process info before exporting.
func BenchmarkSerialize_DeepCopyProcess(b *testing.B) {
	b.StopTimer()
	gen := newRandomEventGenerator(b, Seed)
	encoder := getEncoder()
	evs := gen.GenerateN(b)
	b.StartTimer()

	for i := range b.N {
		ev := evs[i]
		if setter, ok := tetragon.UnwrapGetEventsResponse(ev).(tetragon.ProcessEvent); ok {
			proc := helpers.ResponseGetProcess(ev)
			proc = proto.Clone(proc).(*tetragon.Process)
			setter.SetProcess(proc)
		}
		err := encoder.Encode(ev)
		require.NoError(b, err, "event must encode")
	}
}

// Apply an empty field filter so that we get the effect of the deep copy but don't do
// any filtering.
func BenchmarkSerialize_FieldFilters(b *testing.B) {
	b.StopTimer()
	gen := newRandomEventGenerator(b, Seed)
	encoder := getEncoder()
	evs := gen.GenerateN(b)
	ff, err := NewExcludeFieldFilter([]tetragon.EventType{}, []string{}, false)
	require.NoError(b, err)
	b.StartTimer()

	for i := range b.N {
		ev := evs[i]
		ev, err = ff.Filter(ev)
		require.NoError(b, err, "event must filter")
		err := encoder.Encode(ev)
		require.NoError(b, err, "event must encode")
	}
}

// Apply a field filter that removes the entire process and parent info from the events.
func BenchmarkSerialize_FieldFilters_NoProcessInfo(b *testing.B) {
	b.StopTimer()
	gen := newRandomEventGenerator(b, Seed)
	encoder := getEncoder()
	evs := gen.GenerateN(b)
	ff, err := NewExcludeFieldFilter([]tetragon.EventType{}, []string{"process", "parent"}, false)
	require.NoError(b, err)
	b.StartTimer()

	for i := range b.N {
		ev := evs[i]
		ev, err = ff.Filter(ev)
		require.NoError(b, err, "event must filter")
		err := encoder.Encode(ev)
		require.NoError(b, err, "event must encode")
	}
}

// Apply a field filter that removes the entire process and parent info from the events
// but keeps exec_id and parent_exec_id.
func BenchmarkSerialize_FieldFilters_NoProcesInfoKeepExecid(b *testing.B) {
	b.StopTimer()
	gen := newRandomEventGenerator(b, Seed)
	encoder := getEncoder()
	evs := gen.GenerateN(b)
	ff, err := NewExcludeFieldFilter([]tetragon.EventType{}, []string{"process.pid", "process.binary", "process.uid", "process.cwd", "process.arguments", "process.flags", "process.start_time", "process.auid", "process.pod", "process.docker", "process.refcnt", "process.cap", "process.ns", "process.tid", "process.process_credentials", "process.binary_properties", "parent.pid", "parent.binary", "parent.uid", "parent.cwd", "parent.arguments", "parent.flags", "parent.start_time", "parent.auid", "parent.pod", "parent.docker", "parent.refcnt", "parent.cap", "parent.ns", "parent.tid", "parent.parent_credentials", "parent.binary_properties"}, false)
	require.NoError(b, err)
	b.StartTimer()

	for i := range b.N {
		ev := evs[i]
		ev, err = ff.Filter(ev)
		require.NoError(b, err, "event must filter")
		err = encoder.Encode(ev)
		require.NoError(b, err, "event must encode")
	}
}

// Apply a redaction filter to the event. This doesn't exactly capture how it's done in the real code path but it's a close approximation.
func BenchmarkSerialize_RedactionFilters(b *testing.B) {
	b.StopTimer()
	gen := newRandomEventGenerator(b, Seed)
	encoder := getEncoder()
	evs := gen.GenerateN(b)
	filterList := `{"redact": ["(a)"]}`
	ff, err := ParseRedactionFilterList(filterList)
	require.NoError(b, err)
	b.StartTimer()

	for i := range b.N {
		ev := evs[i]
		getProcess, ok := ev.Event.(interface{ GetProcess() *tetragon.Process })
		if ok {
			process := getProcess.GetProcess()
			process.Arguments, _ = ff.Redact(process.Binary, process.Arguments, []string{""})
		}
		err := encoder.Encode(ev)
		require.NoError(b, err, "event must encode")
	}
}
