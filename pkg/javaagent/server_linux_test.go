// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package javaagent

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakeAgent connects to the server the way the JVMTI agent does and returns
// the connection together with the server reply to its HELLO.
func fakeAgent(t *testing.T, path string) (*net.UnixConn, Header, int, error) {
	t.Helper()
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	payload := make([]byte, 6)
	binary.LittleEndian.PutUint32(payload, ProtoVersion)
	hello, err := (Header{Type: MsgHello}).Message(payload)
	require.NoError(t, err)
	// The server drops a peer it does not know without reading its HELLO.
	_, _ = conn.Write(hello)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, MsgMaxSize)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil || n == 0 {
		if err == nil {
			err = os.ErrClosed
		}
		return conn, Header{}, 0, err
	}
	h, _, err := ParseMessage(buf[:n])
	require.NoError(t, err)
	fds := 0
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	require.NoError(t, err)
	for _, m := range msgs {
		rights, err := unix.ParseUnixRights(&m)
		require.NoError(t, err)
		for _, fd := range rights {
			unix.Close(fd)
			fds++
		}
	}
	return conn, h, fds, nil
}

func TestServerConnected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "java.sock")
	server := NewServer(path, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Listen(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)

	pid := uint32(os.Getpid())
	ticks, err := processStartTicks(os.Getpid())
	require.NoError(t, err)

	// not authorized peer is dropped
	_, _, _, err = fakeAgent(t, path)
	require.Error(t, err)
	require.False(t, server.Connected(pid, ticks))

	// authorized peer is accepted and counts as connected, it gets no
	// ring without a policy
	server.AllowProcess(1, pid, ticks)
	conn, h, fds, err := fakeAgent(t, path)
	require.NoError(t, err)
	require.Equal(t, uint16(MsgAck), uint16(h.Type))
	require.Equal(t, 0, fds)
	// the session is registered right after it is accepted
	connected := func() bool { return server.Connected(pid, ticks) }
	require.Eventually(t, connected, 5*time.Second, 10*time.Millisecond)
	require.False(t, server.Connected(pid, ticks+1))

	// the session ends when the agent closes the connection, the agent
	// that connects again starts new one
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool {
		return !server.Connected(pid, ticks)
	}, 5*time.Second, 10*time.Millisecond)

	_, h, _, err = fakeAgent(t, path)
	require.NoError(t, err)
	require.Equal(t, uint16(MsgAck), uint16(h.Type))
	require.Eventually(t, connected, 5*time.Second, 10*time.Millisecond)
}

// serveAgent acknowledges the server commands and reports the ring setups,
// policy commits and removals it gets.
func serveAgent(conn *net.UnixConn, got chan<- string) {
	buf := make([]byte, MsgMaxSize)
	for {
		_ = conn.SetReadDeadline(time.Time{})
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		h, payload, err := ParseMessage(buf[:n])
		if err != nil {
			return
		}
		switch h.Type {
		case MsgRing:
			got <- fmt.Sprintf("ring %d", binary.LittleEndian.Uint64(payload))
		case MsgPolicyCommit:
			got <- fmt.Sprintf("commit %d", binary.LittleEndian.Uint32(payload))
		case MsgPolicyRemove:
			got <- fmt.Sprintf("remove %d", binary.LittleEndian.Uint32(payload))
		}
		ack := make([]byte, 14)
		binary.LittleEndian.PutUint32(ack, h.Seq)
		msg, err := (Header{Type: MsgAck, Seq: h.Seq}).Message(ack)
		if err != nil {
			return
		}
		if _, err := conn.Write(msg); err != nil {
			return
		}
	}
}

func TestServerPolicyPerProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "java.sock")
	server := NewServer(path, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Listen(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)

	pid := uint32(os.Getpid())
	ticks, err := processStartTicks(os.Getpid())
	require.NoError(t, err)

	policy := func(id uint32) Policy {
		return Policy{
			ID:    id,
			Name:  fmt.Sprintf("policy-%d", id),
			Hooks: []Hook{{PolicyID: id, Kind: HookClass, Class: "pkg/Foo"}},
		}
	}
	got := make(chan string, 16)
	expect := func(want string) {
		t.Helper()
		select {
		case have := <-got:
			require.Equal(t, want, have)
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for %q", want)
		}
	}
	quiet := func() {
		t.Helper()
		select {
		case have := <-got:
			t.Fatalf("unexpected %q", have)
		case <-time.After(200 * time.Millisecond):
		}
	}

	require.NoError(t, server.SetPolicy(policy(1)))
	require.NoError(t, server.SetPolicy(policy(2)))
	require.NoError(t, server.AllowProcess(1, pid, ticks))

	// the agent gets only the policy its process is authorized for, the
	// ring is set up in front of the first policy
	conn, h, _, err := fakeAgent(t, path)
	require.NoError(t, err)
	require.Equal(t, uint16(MsgAck), uint16(h.Type))
	go serveAgent(conn, got)
	expect(fmt.Sprintf("ring %d", RingHdrSize+4<<20))
	expect("commit 1")
	quiet()

	// new policy for another process does not reach it
	require.NoError(t, server.SetPolicy(policy(3)))
	quiet()

	// policy authorized later is applied to the open session, once, and
	// the session keeps its ring
	require.NoError(t, server.AllowProcess(2, pid, ticks))
	expect("commit 2")
	require.NoError(t, server.AllowProcess(2, pid, ticks))
	quiet()

	server.RevokeProcess(2, pid)
	expect("remove 2")

	require.NoError(t, server.RemovePolicy(3))
	quiet()
	require.NoError(t, server.RemovePolicy(1))
	expect("remove 1")
	require.True(t, server.Connected(pid, ticks))
}
