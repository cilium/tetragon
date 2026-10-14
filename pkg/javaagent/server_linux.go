// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaagent

import (
	"bytes"
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
}

type session struct {
	server  *Server
	conn    *net.UnixConn
	pid     uint32
	ring    *Ring
	mu      sync.Mutex
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
	return &Server{
		path:       path,
		sink:       sink,
		policies:   make(map[uint32]Policy),
		sessions:   make(map[*session]struct{}),
		authorized: make(map[uint32]map[uint32]uint64),
	}
}

// AllowProcess authorizes the given policy to attach one process identity to
// the control socket. The PID alone is insufficient because Linux reuses it.
func (s *Server) AllowProcess(policyID, pid uint32, startTicks uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorized[pid] == nil {
		s.authorized[pid] = make(map[uint32]uint64)
	}
	s.authorized[pid][policyID] = startTicks
}

func (s *Server) RevokeProcess(policyID, pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authorized[pid], policyID)
	if len(s.authorized[pid]) == 0 {
		delete(s.authorized, pid)
	}
}

// SetPolicy replaces the active policy snapshot and sends it to attached JVMs.
func (s *Server) SetPolicy(policy Policy) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.mu.Lock()
	if current, ok := s.policies[policy.ID]; ok && current.Name != policy.Name {
		s.mu.Unlock()
		return fmt.Errorf("java policy ID collision between %q and %q", current.Name, policy.Name)
	}
	s.policies[policy.ID] = policy
	sessions := make([]*session, 0, len(s.sessions))
	for c := range s.sessions {
		sessions = append(sessions, c)
	}
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
	ring, err := NewRing(4 << 20)
	if err != nil {
		return
	}
	c := &session{
		server:  s,
		conn:    conn,
		pid:     uint32(pid),
		ring:    ring,
		methods: make(map[uint64]methodDefinition),
		applied: make(map[uint32]bool),
	}
	s.mu.Lock()
	s.sessions[c] = struct{}{}
	policies := make([]Policy, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.sessions, c); s.mu.Unlock(); _ = ring.Close() }()
	if err := c.sendRing(); err != nil {
		return
	}
	for _, p := range policies {
		if err := c.apply(p); err != nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = c.drain(ctx)
}

func processStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	_, rest, ok := bytes.CutLast(data, []byte(")"))
	if !ok {
		return 0, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(rest))
	if len(fields) <= 19 {
		return 0, errors.New("process stat lacks start time")
	}
	return strconv.ParseUint(fields[19], 10, 64)
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

func (c *session) sendRing() error {
	p := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, uint64(len(c.ring.data)))
	msg, err := (Header{Type: MsgRing}).Message(p)
	if err != nil {
		return err
	}
	raw, err := c.conn.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Write(func(fd uintptr) bool {
		rights := unix.UnixRights(c.ring.FD())
		n, e := unix.SendmsgN(int(fd), msg, rights, nil, unix.MSG_NOSIGNAL)
		if errors.Is(e, unix.EAGAIN) {
			return false
		}
		if e != nil {
			sendErr = e
		} else if n != len(msg) {
			sendErr = fmt.Errorf("short Java ring handoff: %d/%d", n, len(msg))
		}
		return true
	})
	if err != nil {
		return err
	}
	return sendErr
}

func (c *session) commandLocked(typ uint16, payload []byte) error {
	c.seq++
	seq := c.seq
	msg, err := (Header{Type: typ, Seq: seq}).Message(payload)
	if err != nil {
		return err
	}
	if _, err = c.conn.Write(msg); err != nil {
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
	for _, hook := range p.Hooks {
		data, err := EncodeHook(hook)
		if err != nil {
			return err
		}
		if err := c.commandLocked(MsgHookAdd, data); err != nil {
			return err
		}
	}
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], p.ID)
	if err := c.commandLocked(MsgPolicyCommit, data[:]); err != nil {
		return err
	}
	c.applied[p.ID] = true
	return nil
}

func (c *session) remove(id uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], id)
	if err := c.commandLocked(MsgPolicyRemove, p[:]); err != nil {
		return err
	}
	delete(c.applied, id)
	return nil
}

func (c *session) drain(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := c.ring.Drain(func(rec Record) error {
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
		notify := (*uint32)(unsafe.Pointer(&c.ring.data[ringOffNotify]))
		waiting := (*uint32)(unsafe.Pointer(&c.ring.data[ringOffConsumerWaiting]))
		atomic.StoreUint32(waiting, 1)
		producerPos := (*uint64)(unsafe.Pointer(&c.ring.data[ringOffProducerPos]))
		consumerPos := (*uint64)(unsafe.Pointer(&c.ring.data[ringOffConsumerPos]))
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
