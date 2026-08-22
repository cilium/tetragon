// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/javaapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/cilium/tetragon/pkg/userringbuf"
)

// TestTimerDrainsUserRingBuffer is intentionally opt-in because it needs BPF
// privileges and a kernel with user ring buffers, BPF timers, syscall
// programs, and BPF_PROG_TEST_RUN support.
func TestTimerDrainsUserRingBuffer(t *testing.T) {
	if os.Getenv("TETRAGON_RUN_PRIVILEGED_TESTS") != "1" {
		t.Skip("set TETRAGON_RUN_PRIVILEGED_TESTS=1 and run as root")
	}

	obj := filepath.Join("..", "..", "..", "bpf", "objs", "bpf_java.o")
	if _, err := os.Stat(obj); err != nil {
		t.Fatalf("build %s first: %v", obj, err)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	require.NoError(t, err)

	var objects struct {
		Init   *ebpf.Program `ebpf:"java_timer_init"`
		User   *ebpf.Map     `ebpf:"tg_java_urb"`
		Events *ebpf.Map     `ebpf:"tg_rb_events"`
		Timers *ebpf.Map     `ebpf:"tg_java_timers"`
		Execve *ebpf.Map     `ebpf:"execve_map"`
	}
	require.NoError(t, spec.LoadAndAssign(&objects, nil))
	t.Cleanup(func() {
		objects.Timers.Close() // dropping this map cancels its timer
		objects.Init.Close()
		objects.User.Close()
		objects.Events.Close()
		objects.Execve.Close()
	})

	reader, err := ringbuf.NewReader(objects.Events)
	require.NoError(t, err)
	defer reader.Close()
	reader.SetDeadline(time.Now().Add(2 * time.Second))

	producer, err := userringbuf.NewProducer(objects.User)
	require.NoError(t, err)
	defer producer.Close()

	ret, err := objects.Init.Run(&ebpf.RunOptions{})
	require.NoError(t, err)
	require.Zero(t, ret)

	submit := func(input javaapi.MsgJava) javaapi.MsgJava {
		var payload bytes.Buffer
		require.NoError(t, binary.Write(&payload, binary.LittleEndian, input))
		require.NoError(t, producer.Submit(payload.Bytes()))

		record, err := reader.Read()
		require.NoError(t, err)
		var output javaapi.MsgJava
		require.NoError(t, binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &output))
		require.Equal(t, uint8(ops.MSG_OP_JAVA), output.Common.Op)
		require.Equal(t, javaapi.MsgJavaSize, output.Common.Size)
		require.Equal(t, input.Common.Ktime, output.Common.Ktime)
		require.Equal(t, input.MethodID, output.MethodID)
		require.Equal(t, input.TID, output.TID)
		return output
	}

	input := javaapi.MsgJava{
		Common:     processapi.MsgCommon{Size: javaapi.MsgJavaSize, Ktime: 987654321},
		ProcessKey: processapi.MsgExecveKey{Pid: 123},
		MethodID:   55,
		TID:        124,
	}
	copy(input.ClassName[:], "example/Foo")
	copy(input.MethodName[:], "work")
	copy(input.Descriptor[:], "()V")

	wantKey := processapi.MsgExecveKey{Pid: input.ProcessKey.Pid, Ktime: 123456789}
	require.NoError(t, objects.Execve.Put(
		execvemap.ExecveKey{Pid: input.ProcessKey.Pid},
		execvemap.ExecveValue{Process: wantKey},
	))
	output := submit(input)
	require.Zero(t, output.Common.Flags&processapi.MSG_COMMON_FLAG_PROCESS_NOT_FOUND)
	require.Equal(t, wantKey, output.ProcessKey)

	input.ProcessKey = processapi.MsgExecveKey{Pid: 125}
	input.Common.Ktime++
	output = submit(input)
	require.NotZero(t, output.Common.Flags&processapi.MSG_COMMON_FLAG_PROCESS_NOT_FOUND)
	require.Equal(t, processapi.MsgExecveKey{Pid: 125, Ktime: input.Common.Ktime}, output.ProcessKey)

	input.ProcessKey = processapi.MsgExecveKey{Pid: 126}
	input.Common.Ktime++
	require.NoError(t, objects.Execve.Put(
		execvemap.ExecveKey{Pid: input.ProcessKey.Pid},
		execvemap.ExecveValue{Process: processapi.MsgExecveKey{Pid: input.ProcessKey.Pid, Ktime: input.Common.Ktime + 1}},
	))
	output = submit(input)
	require.NotZero(t, output.Common.Flags&processapi.MSG_COMMON_FLAG_PROCESS_NOT_FOUND)
	require.Equal(t, processapi.MsgExecveKey{Pid: 126, Ktime: input.Common.Ktime}, output.ProcessKey)
}
