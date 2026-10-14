// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaagent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/reader/proc"
)

// EventSink receives decoded method-entry records. PID is authenticated from
// SO_PEERCRED; it is never accepted from agent-provided record data.
type EventSink func(
	pid, tid uint32,
	ktime, methodID uint64,
	className, methodName, descriptor, policyName, message string,
	tags []string,
)

type Policy struct {
	ID    uint32
	Name  string
	Hooks []Hook
	Meta  map[uint32]HookMetadata
}

type HookMetadata struct {
	Message string
	Tags    []string
}

type Server struct {
	path       string
	sink       EventSink
	updateMu   sync.Mutex
	mu         sync.Mutex
	policies   map[uint32]Policy
	sessions   map[*session]struct{}
	authorized map[uint32]map[uint32]uint64 // pid -> policy id -> process start ticks
	listener   net.Listener
	// data size of the rings created for the sessions
	ringSize atomic.Uint64
}

type session struct {
	server *Server
	conn   *net.UnixConn
	pid    uint32
	// process start ticks, pid alone does not identify the JVM
	startTicks uint64
	// data ring, set up by the first policy applied to the session
	ring atomic.Pointer[Ring]
	mu   sync.Mutex
	// set when the session ends, protected by mu
	closed  bool
	seq     uint32
	methods map[uint64]methodDefinition
	applied map[uint32]bool
}

type methodDefinition struct {
	key                               uint64
	policyID, hookID                  uint32
	className, methodName, descriptor string
}

func NewServer(path string, sink EventSink) *Server {
	s := &Server{
		path:       path,
		sink:       sink,
		policies:   make(map[uint32]Policy),
		sessions:   make(map[*session]struct{}),
		authorized: make(map[uint32]map[uint32]uint64),
	}
	s.ringSize.Store(DefaultRingDataSize)
	return s
}

// SetRingSize sets the data size of the ring that each session gets, it
// needs to be a power of two and at least 1 MiB. It is meant to be called
// before Listen, the rings that already exist keep their size.
func (s *Server) SetRingSize(size uint64) {
	s.ringSize.Store(size)
}

// AllowProcess authorizes the given policy to attach one process identity to
// the control socket. The PID alone is insufficient because Linux reuses it.
// If the agent of the process is already connected, it gets the policy.
func (s *Server) AllowProcess(policyID, pid uint32, startTicks uint64) error {
	s.mu.Lock()
	if s.authorized[pid] == nil {
		s.authorized[pid] = make(map[uint32]uint64)
	}
	s.authorized[pid][policyID] = startTicks
	c := s.sessionLocked(pid, startTicks)
	s.mu.Unlock()
	if c == nil {
		return nil
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.mu.Lock()
	policy, ok := s.policies[policyID]
	ok = ok && s.authorized[pid][policyID] == startTicks
	s.mu.Unlock()
	if !ok {
		return nil
	}
	return c.apply(policy)
}

// RevokeProcess takes the authorization back. If the agent of the process
// is connected, the policy is removed from it.
func (s *Server) RevokeProcess(policyID, pid uint32) {
	s.mu.Lock()
	startTicks, ok := s.authorized[pid][policyID]
	delete(s.authorized[pid], policyID)
	if len(s.authorized[pid]) == 0 {
		delete(s.authorized, pid)
	}
	var c *session
	if ok {
		c = s.sessionLocked(pid, startTicks)
	}
	s.mu.Unlock()
	if c == nil {
		return
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	_ = c.remove(policyID)
}

// sessionLocked returns the control session of the given process identity.
// Called with s.mu held.
func (s *Server) sessionLocked(pid uint32, startTicks uint64) *session {
	for c := range s.sessions {
		if c.pid == pid && c.startTicks == startTicks {
			return c
		}
	}
	return nil
}

// sessionsLocked returns the control sessions of the processes the policy
// is authorized for. Called with s.mu held.
func (s *Server) sessionsLocked(policyID uint32) []*session {
	var sessions []*session
	for c := range s.sessions {
		if start, ok := s.authorized[c.pid][policyID]; ok && start == c.startTicks {
			sessions = append(sessions, c)
		}
	}
	return sessions
}

// Connected reports whether the agent of the given JVM has a control session
// open. That is also the case for an agent that was loaded into the JVM by
// previous Tetragon instance and connected back on its own.
func (s *Server) Connected(pid uint32, startTicks uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionLocked(pid, startTicks) != nil
}

// SetPolicy replaces the active policy snapshot and sends it to attached JVMs
// the policy is authorized for.
func (s *Server) SetPolicy(policy Policy) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.mu.Lock()
	if current, ok := s.policies[policy.ID]; ok && current.Name != policy.Name {
		s.mu.Unlock()
		return fmt.Errorf("java policy ID collision between %q and %q", current.Name, policy.Name)
	}
	s.policies[policy.ID] = policy
	sessions := s.sessionsLocked(policy.ID)
	s.mu.Unlock()
	var errs []error
	for _, c := range sessions {
		if err := c.apply(policy); err != nil {
			errs = append(errs, fmt.Errorf("JVM %d: %w", c.pid, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Server) RemovePolicy(id uint32) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.mu.Lock()
	delete(s.policies, id)
	for pid, policies := range s.authorized {
		delete(policies, id)
		if len(policies) == 0 {
			delete(s.authorized, pid)
		}
	}
	sessions := make([]*session, 0, len(s.sessions))
	for c := range s.sessions {
		sessions = append(sessions, c)
	}
	s.mu.Unlock()
	var errs []error
	for _, c := range sessions {
		if err := c.remove(id); err != nil {
			errs = append(errs, fmt.Errorf("JVM %d: %w", c.pid, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Server) Listen(ctx context.Context) error {
	if s.path == "" || !filepath.IsAbs(s.path) || strings.ContainsRune(s.path, '\x00') {
		return fmt.Errorf("invalid Java IPC socket path %q", s.path)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	_ = os.Remove(s.path)
	addr := &net.UnixAddr{Name: s.path, Net: "unixpacket"}
	l, err := net.ListenUnix("unixpacket", addr)
	if err != nil {
		return fmt.Errorf("listen on Java IPC socket: %w", err)
	}
	s.listener = l
	if err := os.Chmod(s.path, 0666); err != nil {
		l.Close()
		return err
	}
	defer os.Remove(s.path)
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn *net.UnixConn) {
	defer conn.Close()
	pid, err := peerPID(conn)
	if err != nil || pid <= 1 {
		return
	}
	startTicks, err := processStartTicks(pid)
	if err != nil {
		return
	}
	s.mu.Lock()
	allowed := s.authorized[uint32(pid)]
	valid := false
	for _, start := range allowed {
		if start == startTicks {
			valid = true
			break
		}
	}
	s.mu.Unlock()
	if !valid {
		return
	}
	buf := make([]byte, MsgMaxSize)
	n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
	if err != nil || flags&unix.MSG_TRUNC != 0 {
		return
	}
	h, payload, err := ParseMessage(buf[:n])
	if err != nil || h.Type != MsgHello || len(payload) < 4 {
		return
	}
	version := binary.LittleEndian.Uint32(payload[:4])
	if version != ProtoVersion {
		return
	}
	c := &session{
		server:     s,
		conn:       conn,
		pid:        uint32(pid),
		startTicks: startTicks,
		methods:    make(map[uint64]methodDefinition),
		applied:    make(map[uint32]bool),
	}
	defer c.close()
	// Accept the session, the agent waits for it. The session gets
	// commands only after it is registered below, the data ring is set up
	// by the first policy that is applied to it.
	if err := c.sendAck(h.Seq); err != nil {
		return
	}
	s.updateMu.Lock()
	s.mu.Lock()
	s.sessions[c] = struct{}{}
	policies := make([]Policy, 0, len(s.policies))
	for id, start := range s.authorized[c.pid] {
		if p, ok := s.policies[id]; ok && start == c.startTicks {
			policies = append(policies, p)
		}
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.sessions, c); s.mu.Unlock() }()
	for _, p := range policies {
		if err := c.apply(p); err != nil {
			s.updateMu.Unlock()
			return
		}
	}
	s.updateMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = c.drain(ctx)
}

// processStartTicks returns the start time of the process, which together
// with the pid identifies the process.
func processStartTicks(pid int) (uint64, error) {
	stats, err := proc.GetProcStatStrings(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return 0, err
	}
	return proc.GetStatsStartTicks(stats)
}

func peerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		cred, inner = unix.GetsockoptUcred(
			int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED,
		)
	})
	if err != nil {
		return 0, err
	}
	if inner != nil {
		return 0, inner
	}
	return int(cred.Pid), nil
}

// sendAck accepts the session, it answers the HELLO of the agent.
func (c *session) sendAck(seq uint32) error {
	// u32 seq, i32 status, u32 classes, u16 error length
	p := make([]byte, 14)
	binary.LittleEndian.PutUint32(p, seq)
	msg, err := (Header{Type: MsgAck, Seq: seq}).Message(p)
	if err != nil {
		return err
	}
	return c.send(msg, -1)
}

// close releases the data ring when the session ends.
func (c *session) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if ring := c.ring.Swap(nil); ring != nil {
		ring.Close()
	}
}

// ringLocked sets up the data ring of the session, unless it has one
// already. Called with c.mu held.
func (c *session) ringLocked() error {
	if c.ring.Load() != nil {
		return nil
	}
	if c.closed {
		return errors.New("java agent session is closed")
	}
	ring, err := NewRing(c.server.ringSize.Load())
	if err != nil {
		return err
	}
	p := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, uint64(len(ring.data)))
	// The agent maps the ring before it acknowledges the command.
	if err := c.commandLocked(MsgRing, p, ring.FD()); err != nil {
		ring.Close()
		return err
	}
	c.ring.Store(ring)
	return nil
}

// send writes one message to the agent, passing it the file descriptor
// along if fd is not negative.
func (c *session) send(msg []byte, passFD int) error {
	if passFD < 0 {
		_, err := c.conn.Write(msg)
		return err
	}
	raw, err := c.conn.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Write(func(fd uintptr) bool {
		rights := unix.UnixRights(passFD)
		n, e := unix.SendmsgN(int(fd), msg, rights, nil, unix.MSG_NOSIGNAL)
		if errors.Is(e, unix.EAGAIN) {
			return false
		}
		if e != nil {
			sendErr = e
		} else if n != len(msg) {
			sendErr = fmt.Errorf("short Java agent message: %d/%d", n, len(msg))
		}
		return true
	})
	if err != nil {
		return err
	}
	return sendErr
}

// commandLocked sends one command to the agent and waits for its
// acknowledgement, passFD is the file descriptor to pass along with the
// command, -1 for none. Called with c.mu held.
func (c *session) commandLocked(typ uint16, payload []byte, passFD int) error {
	c.seq++
	seq := c.seq
	msg, err := (Header{Type: typ, Seq: seq}).Message(payload)
	if err != nil {
		return err
	}
	if err = c.send(msg, passFD); err != nil {
		return err
	}
	buf := make([]byte, MsgMaxSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	n, err := c.conn.Read(buf)
	if err != nil {
		return err
	}
	h, data, err := ParseMessage(buf[:n])
	if err != nil {
		return err
	}
	if h.Type != MsgAck || h.Seq != seq {
		return fmt.Errorf("unexpected JVMTI acknowledgement type=%d seq=%d", h.Type, h.Seq)
	}
	if len(data) < 12 {
		return errors.New("truncated JVMTI acknowledgement")
	}
	status := int32(binary.LittleEndian.Uint32(data[4:8]))
	if status != 0 {
		return fmt.Errorf("JVMTI agent rejected command: %d", status)
	}
	return nil
}

func (c *session) apply(p Policy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.applied[p.ID] {
		return nil
	}
	// The hooked methods report through the ring.
	if err := c.ringLocked(); err != nil {
		return err
	}
	for _, hook := range p.Hooks {
		data, err := EncodeHook(hook)
		if err != nil {
			return err
		}
		if err := c.commandLocked(MsgHookAdd, data, -1); err != nil {
			return err
		}
	}
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], p.ID)
	if err := c.commandLocked(MsgPolicyCommit, data[:], -1); err != nil {
		return err
	}
	c.applied[p.ID] = true
	return nil
}

func (c *session) remove(id uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.applied[id] {
		return nil
	}
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], id)
	if err := c.commandLocked(MsgPolicyRemove, p[:], -1); err != nil {
		return err
	}
	delete(c.applied, id)
	return nil
}

// hangup reports whether the agent side of the control connection is closed.
func (c *session) hangup() bool {
	raw, err := c.conn.SyscallConn()
	if err != nil {
		return true
	}
	closed := false
	err = raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}}
		n, e := unix.Poll(fds, 0)
		closed = e == nil && n == 1 &&
			fds[0].Revents&(unix.POLLHUP|unix.POLLRDHUP|unix.POLLERR) != 0
	})
	return err != nil || closed
}

// drain reads the records from the data ring until the session ends. The
// ring shows up when the first policy is applied to the session.
func (c *session) drain(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ring := c.ring.Load()
		if ring == nil {
			// No policy needed the ring yet, just watch the connection.
			time.Sleep(100 * time.Millisecond)
			if c.hangup() {
				return errors.New("java agent closed the control connection")
			}
			continue
		}
		err := ring.Drain(func(rec Record) error {
			switch rec.Type {
			case RecMethodDef:
				return c.methodDef(rec.Data)
			case RecMethodEntry:
				return c.methodEntry(rec.Data)
			default:
				return fmt.Errorf("unknown Java ring record type %d", rec.Type)
			}
		})
		if err != nil {
			return err
		}
		// The native producer wakes this word when the consumer is waiting. A
		// bounded futex wait also notices JVM termination without a wakeup.
		notify := (*uint32)(unsafe.Pointer(&ring.data[ringOffNotify]))
		waiting := (*uint32)(unsafe.Pointer(&ring.data[ringOffConsumerWaiting]))
		atomic.StoreUint32(waiting, 1)
		producerPos := (*uint64)(unsafe.Pointer(&ring.data[ringOffProducerPos]))
		consumerPos := (*uint64)(unsafe.Pointer(&ring.data[ringOffConsumerPos]))
		if atomic.LoadUint64(producerPos) == atomic.LoadUint64(consumerPos) {
			ts := unix.NsecToTimespec(int64(100 * time.Millisecond))
			_, _, errno := unix.Syscall6(
				unix.SYS_FUTEX,
				uintptr(unsafe.Pointer(notify)),
				0,
				uintptr(atomic.LoadUint32(notify)),
				uintptr(unsafe.Pointer(&ts)),
				0,
				0,
			)
			if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR && errno != unix.ETIMEDOUT {
				return errno
			}
		}
		atomic.StoreUint32(waiting, 0)
		// The agent closes the connection when it gives up on the session
		// and connects again, and so does the kernel when the JVM exits.
		if c.hangup() {
			return errors.New("java agent closed the control connection")
		}
	}
}

func (c *session) methodDef(data []byte) error {
	if len(data) < 24 {
		return errors.New("truncated Java method definition")
	}
	key := binary.LittleEndian.Uint64(data[:8])
	pol := binary.LittleEndian.Uint32(data[8:12])
	hook := binary.LittleEndian.Uint32(data[12:16])
	cl := int(binary.LittleEndian.Uint16(data[16:18]))
	nl := int(binary.LittleEndian.Uint16(data[18:20]))
	dl := int(binary.LittleEndian.Uint16(data[20:22]))
	used := 24 + cl + nl + dl
	padding := (RecAlign - used%RecAlign) % RecAlign
	if used > len(data) || len(data)-used != padding {
		return errors.New("invalid Java method definition lengths")
	}
	for _, b := range data[used:] {
		if b != 0 {
			return errors.New("nonzero Java method definition padding")
		}
	}
	c.methods[key] = methodDefinition{
		key:        key,
		policyID:   pol,
		hookID:     hook,
		className:  string(data[24 : 24+cl]),
		methodName: string(data[24+cl : 24+cl+nl]),
		descriptor: string(data[24+cl+nl : used]),
	}
	return nil
}

func (c *session) methodEntry(data []byte) error {
	if len(data) < 24 {
		return errors.New("truncated Java method entry")
	}
	key := binary.LittleEndian.Uint64(data[:8])
	ktime := binary.LittleEndian.Uint64(data[8:16])
	tid := binary.LittleEndian.Uint32(data[16:20])
	def, ok := c.methods[key]
	if !ok {
		return nil
	}
	c.server.mu.Lock()
	p, ok := c.server.policies[def.policyID]
	c.server.mu.Unlock()
	if !ok || c.server.sink == nil {
		return nil
	}
	meta := p.Meta[def.hookID]
	c.server.sink(
		c.pid,
		tid,
		ktime,
		stableMethodID(def.className, def.methodName, def.descriptor),
		def.className,
		def.methodName,
		def.descriptor,
		p.Name,
		meta.Message,
		meta.Tags,
	)
	return nil
}

func stableMethodID(className, methodName, descriptor string) uint64 {
	h := fnv.New64a()
	for _, value := range []string{className, methodName, descriptor} {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}
