// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"container/list"
	"fmt"
	"reflect"
	"strings"
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// NB(kkourt): this package is in a somewhat unstable state since I'm
// experimenting with different approaches and tradeoffs. Once its interface
// stabilizes somewhat, I'd like to investigate generating code directly from
// the protbuf descriptions via a protoc plugin.

const (
	CapsEffective   = 0
	CapsInheritable = 1
	CapsPermitted   = 2
)

// ResponseChecker checks a single response
type ResponseChecker interface {
	// Check checks a single response.
	Check(*tetragon.GetEventsResponse, Logger) error
}

// ResponseCheckerFn is a wrapper that allows a function to be used as an eventChecker
type ResponseCheckerFn func(*tetragon.GetEventsResponse, Logger) error

// Check implements ResponseChecker interface
func (f ResponseCheckerFn) Check(e *tetragon.GetEventsResponse, log Logger) error {
	return f(e, log)
}

// MultiResponseChecker is a stateful checker for checking a series of responses
type MultiResponseChecker interface {
	// NextCheck checks a response and returns a boolean value indicating
	// whether the checker has concluded, and an error indicating whether the
	// check was successful. The boolean value allows short-circuting checks.
	//
	// Specifically:
	// (false,  nil): this response check was successful, but need to check more events
	// (false, !nil): this response check not was successful, but need to check more events
	// (true,   nil): checker was successful, no need to check more responses
	// (true,  !nil): checker failed, no need to check more responses
	NextCheck(*tetragon.GetEventsResponse, Logger) (bool, error)

	// FinalCheck indicates that the sequence of events has ended, and asks
	// the checker to make a final decision.
	FinalCheck(Logger) error

	// Reset resets the checker so that it can be used again
	Reset()
}

// MultiResponseCheckerFns is a wrapper that enables functions to be used as a stateful
// checker for checking a series of responses
type MultiResponseCheckerFns struct {
	NextCheckFn  func(*tetragon.GetEventsResponse, Logger) (bool, error)
	FinalCheckFn func(Logger) error
	ResetFn      func()
}

// NextCheck calls NextCheckFn
func (fns *MultiResponseCheckerFns) NextCheck(r *tetragon.GetEventsResponse, l Logger) (bool, error) {
	return fns.NextCheckFn(r, l)
}

// FinalCheck calls FinalCheckFn
func (fns *MultiResponseCheckerFns) FinalCheck(l Logger) error {
	return fns.FinalCheckFn(l)
}

// Reset calls ResetFn
func (fns *MultiResponseCheckerFns) Reset() {
	fns.ResetFn()
}

// OrderedMultiResponseChecker matches a list of ResponseCheckers over a sequence of responses
type OrderedMultiResponseChecker struct {
	checkers []ResponseChecker
	idx      int
}

// NewOrderedMultiResponseChecker returns a new OrderedMultiResponseChecker
func NewOrderedMultiResponseChecker(checkers ...ResponseChecker) OrderedMultiResponseChecker {
	return OrderedMultiResponseChecker{
		checkers: checkers,
		idx:      0,
	}
}

// NextCheck verifies that the next check succeeds in the chain
func (c *OrderedMultiResponseChecker) NextCheck(r *tetragon.GetEventsResponse, l Logger) (bool, error) {
	// all checkers have been verified
	if c.idx >= len(c.checkers) {
		return true, nil
	}

	err := c.checkers[c.idx].Check(r, l)
	if err != nil {
		return false, err
	}

	c.idx++
	if c.idx == len(c.checkers) {
		l.Logf("OrderedMultiResponseChecker: all %d checks succeeded", len(c.checkers))
		return true, nil
	}

	l.Logf("OrderedMultiResponseChecker: %d/%d matched", c.idx, len(c.checkers))
	return false, nil
}

// FinalCheck verifies that all checks in the chain have succeeded
func (c *OrderedMultiResponseChecker) FinalCheck(l Logger) error {
	if c.idx >= len(c.checkers) {
		return nil
	}
	return fmt.Errorf("OrderedMultiResponseChecker: only %d/%d matched", c.idx, len(c.checkers))
}

// Reset resets the internal state of OrderedMultiResponseChecker
func (c *OrderedMultiResponseChecker) Reset() {
	c.idx = 0
}

// Append adds a new checker to the list of checkers
func (c *OrderedMultiResponseChecker) Append(checkers ...ResponseChecker) {
	for _, checker := range checkers {
		c.checkers = append(c.checkers, checker)
	}
}

// NewSingleMultiResponseChecker checks all responses against a single checker
func NewSingleMultiResponseChecker(checker ResponseChecker) MultiResponseChecker {
	// NB: no need for a separate implementation
	ret := NewOrderedMultiResponseChecker(checker)
	return &ret
}

// AllMultiResponseChecker matches all checkers for all responses
type AllMultiResponseChecker struct {
	checkers []ResponseChecker
}

// NewAllMultiResponseChecker returns a new AllMultiResponseChecker
func NewAllMultiResponseChecker(checkers ...ResponseChecker) AllMultiResponseChecker {
	return AllMultiResponseChecker{
		checkers: checkers,
	}
}

// NextCheck verifies that all checks in the AllMultiResponseChecker succeeded. Otherwise,
// we bail out
func (c *AllMultiResponseChecker) NextCheck(r *tetragon.GetEventsResponse, l Logger) (bool, error) {
	for i := range c.checkers {
		if err := c.checkers[i].Check(r, l); err != nil {
			return true, err
		}
	}
	return false, nil
}

// FinalCheck logs that all checks have succeeded
func (c *AllMultiResponseChecker) FinalCheck(l Logger) error {
	l.Logf("AllMultiResponseChecker: all %d checks succeeded for all events", len(c.checkers))
	return nil
}

// Reset is a nop in AllMultiResponseChecker
func (c *AllMultiResponseChecker) Reset() {}

// UnorderedMultiResponseChecker matches a list of ResponseCheckers over a
// squence of responses. The checkers can match in any order (no
// backtracking).
type UnorderedMultiResponseChecker struct {
	pendingCheckers *list.List
	totalCheckers   int

	allCheckers *list.List
}

// NewUnorderedMultiResponseChecker creates a new UnorderedMultiResponseChecker
func NewUnorderedMultiResponseChecker(checkers ...ResponseChecker) *UnorderedMultiResponseChecker {
	allList := list.New()
	for _, c := range checkers {
		allList.PushBack(c)
	}

	pendingList := list.New()
	pendingList.PushBackList(allList)

	return &UnorderedMultiResponseChecker{
		allCheckers:     allList,
		pendingCheckers: pendingList,
		totalCheckers:   len(checkers),
	}
}

// Reset resets the list of pending checkers in the UnorderedMultiResponseChecker
func (c *UnorderedMultiResponseChecker) Reset() {
	c.pendingCheckers = list.New()
	c.pendingCheckers.PushBackList(c.allCheckers)
	c.totalCheckers = c.pendingCheckers.Len()

}

// NextCheck calls the next pending checker in the pending queue until we run out of events
func (c *UnorderedMultiResponseChecker) NextCheck(ev *tetragon.GetEventsResponse, log Logger) (bool, error) {
	clen := c.pendingCheckers.Len()
	if clen == 0 {
		return true, nil
	}

	log.Logf("UnorderedMultiResponseChecker: %d/%d checkers remain", clen, c.totalCheckers)
	idx := 1
	for e := c.pendingCheckers.Front(); e != nil; e = e.Next() {
		checker := e.Value.(ResponseChecker)
		err := checker.Check(ev, log)
		if err == nil {
			log.Logf("UnorderedMultiResponseChecker: checking %d/%d: success", idx, clen)
			c.pendingCheckers.Remove(e)
			clen--
			if clen > 0 {
				log.Logf("UnorderedMultiResponseChecker: success: %d/%d matchers remaining", clen, c.totalCheckers)
				return false, nil
			}

			log.Logf("UnorderedMultiResponseChecker: success: all %d matches matched", c.totalCheckers)
			return true, nil
		}
		log.Logf("UnorderedMultiResponseChecker: checking %d/%d: failure: %s", idx, clen, err)
		idx++
	}

	return false, fmt.Errorf("UnorderedMultiResponseChecker: all %d checks failed", c.pendingCheckers.Len())
}

// FinalCheck verifies that all checkers succeeded
func (c *UnorderedMultiResponseChecker) FinalCheck(log Logger) error {
	if l := c.pendingCheckers.Len(); l == 0 {
		return nil
	}
	return fmt.Errorf("UnorderedMultiResponseChecker: %d checks remain", c.pendingCheckers.Len())
}

// Append adds a new checker to the list of checkers
func (c *UnorderedMultiResponseChecker) Append(checkers ...ResponseChecker) {
	for _, checker := range checkers {
		c.pendingCheckers.PushBack(checker)
		c.totalCheckers++
	}
}

type tetragonEvent interface {
	// used for TETRAGON events such as:
	// tetragon.ProcessExec
	// tetragon.ProcessClose
	// etc.
}

// EventChainChecker is a checker that verifies a chain of events
type EventChainChecker struct {
	responseCheck func(*tetragon.GetEventsResponse, Logger) (tetragonEvent, error)
	eventCheck    func(tetragonEvent, Logger) error
}

func eventGetProcess(ev tetragonEvent) *tetragon.Process {
	switch v := ev.(type) {
	case *tetragon.ProcessExec:
		return v.Process
	case *tetragon.ProcessDns:
		return v.Process
	case *tetragon.ProcessExit:
		return v.Process
	case *tetragon.ProcessKprobe:
		return v.Process
	case *tetragon.ProcessTracepoint:
		return v.Process
	default:
		panic(fmt.Sprintf("Unhandled type %T", v))
	}
}

func eventGetParent(ev tetragonEvent) *tetragon.Process {
	switch v := ev.(type) {
	case *tetragon.ProcessExec:
		return v.Parent
	case *tetragon.ProcessDns:
		return nil
	case *tetragon.ProcessExit:
		return v.Parent
	}
	return nil
}

func EventTypeString(ev interface{}) string {
	switch xev := ev.(type) {
	case *tetragon.GetEventsResponse_ProcessDns:
		return "ProcessDns"
	case *tetragon.GetEventsResponse_ProcessExec:
		return fmt.Sprintf("ProcessExec(proc.cmd=%s)", xev.ProcessExec.Process.Binary)
	case *tetragon.GetEventsResponse_ProcessExit:
		return "ProcessExit"
	case *tetragon.GetEventsResponse_Test:
		return "Test"
	case *tetragon.GetEventsResponse_ProcessKprobe:
		return fmt.Sprintf("Kprobe(proc.cmd=%s)", xev.ProcessKprobe.Process.Binary)
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		return fmt.Sprintf("Tracepoint(event=%s)", xev.ProcessTracepoint.Event)
	default:
		return fmt.Sprintf("<UNKNOWN:%T>", ev)
	}
}

// EventTypeError represents an error checking the event type
type EventTypeError struct {
	Err error
}

func (e EventTypeError) Error() string {
	return e.Err.Error()
}

func checkEvent(r *tetragon.GetEventsResponse, l Logger, types ...tetragon.EventType) (tetragonEvent, error) {

	checkTypes := func(ty tetragon.EventType) error {
		for i := range types {
			if types[i] == ty {
				return nil
			}
		}
		return EventTypeError{
			Err: fmt.Errorf("type %s not in %+v", tetragon.EventType_name[int32(ty)], types),
		}
	}

	switch ev := r.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		if err := checkTypes(tetragon.EventType_PROCESS_EXEC); err != nil {
			return nil, err
		}
		return ev.ProcessExec, nil

	case *tetragon.GetEventsResponse_ProcessExit:
		if err := checkTypes(tetragon.EventType_PROCESS_EXIT); err != nil {
			return nil, err
		}
		return ev.ProcessExit, nil

	case *tetragon.GetEventsResponse_ProcessDns:
		if err := checkTypes(tetragon.EventType_PROCESS_DNS); err != nil {
			return nil, err
		}
		return ev.ProcessDns, nil

	case *tetragon.GetEventsResponse_ProcessTracepoint:
		if err := checkTypes(tetragon.EventType_PROCESS_TRACEPOINT); err != nil {
			return nil, err
		}
		return ev.ProcessTracepoint, nil

	case *tetragon.GetEventsResponse_ProcessKprobe:
		if err := checkTypes(tetragon.EventType_PROCESS_KPROBE); err != nil {
			return nil, err
		}
		return ev.ProcessKprobe, nil

	case *tetragon.GetEventsResponse_Test:
		if err := checkTypes(tetragon.EventType_TEST); err != nil {
			return nil, err
		}
		return ev.Test, nil
	}

	return fmt.Errorf("Unknown event type (%T)", r.Event), nil
}

// NewExecEventChecker creates a new EventChainChecker for Exec events
func NewExecEventChecker() *EventChainChecker {
	return &EventChainChecker{
		responseCheck: func(r *tetragon.GetEventsResponse, l Logger) (tetragonEvent, error) {
			return checkEvent(r, l, tetragon.EventType_PROCESS_EXEC)
		},
		eventCheck: func(ev tetragonEvent, l Logger) error {
			return nil
		},
	}
}

// NewExitEventChecker creates a new EventChainChecker for Exit Events
func NewExitEventChecker() *EventChainChecker {
	return &EventChainChecker{
		responseCheck: func(r *tetragon.GetEventsResponse, l Logger) (tetragonEvent, error) {
			return checkEvent(r, l, tetragon.EventType_PROCESS_EXIT)
		},
		eventCheck: func(ev tetragonEvent, l Logger) error {
			return nil
		},
	}
}

// NewTestEventChecker creates a new EventChainChecker for Test events
func NewTestEventChecker() *EventChainChecker {
	return &EventChainChecker{
		responseCheck: func(r *tetragon.GetEventsResponse, l Logger) (tetragonEvent, error) {
			return checkEvent(r, l, tetragon.EventType_TEST)
		},
		eventCheck: func(ev tetragonEvent, l Logger) error {
			return nil
		},
	}
}

// NewDNSEventChecker creates a new EventChainChecker for DNS events
func NewDNSEventChecker() *EventChainChecker {
	return &EventChainChecker{
		responseCheck: func(r *tetragon.GetEventsResponse, l Logger) (tetragonEvent, error) {
			return checkEvent(r, l, tetragon.EventType_PROCESS_DNS)
		},
		eventCheck: func(ev tetragonEvent, l Logger) error {
			return nil
		},
	}
}

// End ends the chain
func (e *EventChainChecker) End() ResponseChecker {
	fn := func(r *tetragon.GetEventsResponse, l Logger) error {
		ev, err := e.responseCheck(r, l)
		if err != nil {
			return err
		}
		return e.eventCheck(ev, l)
	}
	return ResponseCheckerFn(fn)
}

func eventHasDstIP(e tetragonEvent, ip string) error {
	if ev, ok := e.(interface{ GetDestinationIp() string }); ok {
		evIP := ev.GetDestinationIp()
		if evIP == ip {
			return nil
		}
		return fmt.Errorf("Expecting DstIP %s but %T has %s", ip, ev, evIP)
	}
	return fmt.Errorf("type %T does not have DstIP", e)
}

// HasDstIP adds a check that the event has a destination IP value matching to the argument
func (e *EventChainChecker) HasDstIP(ip string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasDstIP(e, ip)
	}
	return e
}

func eventHasSrcIP(e tetragonEvent, ip string) error {
	if ev, ok := e.(interface{ GetSourceIp() string }); ok {
		evIP := ev.GetSourceIp()
		if evIP == ip {
			return nil
		}
		return fmt.Errorf("Expecting SrcIP %s but %T has %s", ip, ev, evIP)
	}
	return fmt.Errorf("type %T does not have SrcIP", e)
}

// HasSrcIP adds a check that the event has a source IP value matching to the argument
func (e *EventChainChecker) HasSrcIP(ip string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSrcIP(e, ip)
	}
	return e
}

func eventHasSignal(e tetragonEvent, s syscall.Signal) error {
	if ev, ok := e.(interface {
		GetSignal() string
	}); ok {
		evSignal := ev.GetSignal()
		if evSignal == unix.SignalName(s) {
			return nil
		}
	}
	return fmt.Errorf("type %T does not have signal", e)
}

func (e *EventChainChecker) HasSignal(s syscall.Signal) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSignal(e, s)
	}
	return e
}

func eventHasType(e tetragonEvent, proto string) error {
	if ev, ok := e.(interface {
		GetSocketType() string
	}); ok {
		evProto := ev.GetSocketType()
		if evProto == proto {
			return nil
		}
		return fmt.Errorf("Expecting Type %s but %T has %s", proto, ev, evProto)
	}
	return fmt.Errorf("type %T does not have Type", e)
}

// HasType adds a check that the event has the expected socket type
func (e *EventChainChecker) HasType(proto string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasType(e, proto)
	}
	return e
}

func checkPort(port uint32, val *wrapperspb.UInt32Value) error {
	if val == nil {
		return fmt.Errorf("%d does not match nil value", port)
	}
	if val.Value != port {
		return fmt.Errorf("%d does not match %d value", port, val.Value)
	}
	return nil
}

func eventHasDstPort(e tetragonEvent, port uint32) error {
	if ev, ok := e.(interface {
		GetDestinationPort() *wrapperspb.UInt32Value
	}); ok {
		evPort := ev.GetDestinationPort()
		err := checkPort(port, evPort)
		if err == nil {
			return nil
		}
		return fmt.Errorf("%T port check failed: %w", ev, err)
	}
	return fmt.Errorf("type %T does not have Dst Port", e)
}

// HasDstPort adds a check that the event has a destination port value matching to the argument
func (e *EventChainChecker) HasDstPort(port uint32) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasDstPort(e, port)
	}
	return e
}

func eventHasSrcPort(e tetragonEvent, port uint32) error {
	if ev, ok := e.(interface {
		GetSourcePort() *wrapperspb.UInt32Value
	}); ok {
		evPort := ev.GetSourcePort()
		err := checkPort(port, evPort)
		if err == nil {
			return nil
		}
		return fmt.Errorf("%T port check failed: %w", ev, err)
	}
	return fmt.Errorf("type %T does not have Src Port", e)
}

// HasSrcPort adds a check that the event has a source port value matching to the argument
func (e *EventChainChecker) HasSrcPort(port uint32) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSrcPort(e, port)
	}
	return e
}

func eventHasIP(e tetragonEvent, IP string) error {
	if ev, ok := e.(interface{ GetIp() string }); ok {
		evIP := ev.GetIp()
		if evIP == IP {
			return nil
		}
		return fmt.Errorf("Expecting IP %s but %T has %s", IP, ev, evIP)
	}
	return fmt.Errorf("type %T does not have IP", e)
}

// HasIP adds a check that the event has an IP matching the argument
func (e *EventChainChecker) HasIP(IP string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasIP(e, IP)
	}
	return e
}

func eventHasPort(e tetragonEvent, port uint32) error {
	if ev, ok := e.(interface {
		GetPort() *wrapperspb.UInt32Value
	}); ok {
		evPort := ev.GetPort()
		err := checkPort(port, evPort)
		if err == nil {
			return nil
		}
		return fmt.Errorf("%T port check failed: %w", ev, err)
	}
	return fmt.Errorf("type %T does not have IP", e)
}

// HasPort adds a check that the event has an port matching the argument
func (e *EventChainChecker) HasPort(port uint32) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasPort(e, port)
	}
	return e
}

func eventHasNegotiatedVersion(e tetragonEvent, version string) error {
	if ev, ok := e.(interface{ GetNegotiatedVersion() string }); ok {
		evVersion := ev.GetNegotiatedVersion()
		if evVersion == version {
			return nil
		}
		return fmt.Errorf("Expecting NegotiatedVersion %s but %T has %s", version, ev, evVersion)
	}
	return fmt.Errorf("type %T does not have NegotiatedVersion", e)
}

// HasNegotiatedVersion adds a check that the event has a negotiated TLS version matching
// the argument
func (e *EventChainChecker) HasNegotiatedVersion(version string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasNegotiatedVersion(e, version)
	}
	return e
}

func eventHasSupportedVersions(e tetragonEvent, versions []string) error {
	if ev, ok := e.(interface{ GetSupportedVersions() string }); ok {
		evVersionsString := ev.GetSupportedVersions()
		evVersions := strings.Split(evVersionsString, " ")
		evVersionsSet := make(map[string]bool)
		for _, version := range evVersions {
			evVersionsSet[version] = true
		}
		versionsSet := make(map[string]bool)
		for _, version := range versions {
			versionsSet[version] = true
		}
		if reflect.DeepEqual(versionsSet, evVersionsSet) {
			return nil
		}
		return fmt.Errorf("Expecting SupportedVersions %s but %T has %s", versions, ev, evVersions)
	}
	return fmt.Errorf("type %T does not have SupportedVersions", e)
}

// HasSupportedVersions adds a check that the event has a set of supported versions
// exactly matching the set of versions given as an argument
func (e *EventChainChecker) HasSupportedVersions(versions []string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSupportedVersions(e, versions)
	}
	return e
}

func eventHasSniType(e tetragonEvent, _type string) error {
	if ev, ok := e.(interface{ GetSniType() string }); ok {
		evType := ev.GetSniType()
		if evType == _type {
			return nil
		}
		return fmt.Errorf("Expecting SniType %s but %T has %s", _type, ev, evType)
	}
	return fmt.Errorf("type %T does not have SniType", e)
}

// HasSniType adds a check that the event has a negotiated TLS type matching
// the argument
func (e *EventChainChecker) HasSniType(_type string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSniType(e, _type)
	}
	return e
}

func eventHasSniName(e tetragonEvent, name string) error {
	if ev, ok := e.(interface{ GetSniName() string }); ok {
		evName := ev.GetSniName()
		if evName == name {
			return nil
		}
		return fmt.Errorf("Expecting SniName %s but %T has %s", name, ev, evName)
	}
	return fmt.Errorf("type %T does not have SniName", e)
}

// HasSniName adds a check that the event has a negotiated TLS name matching
// the argument
func (e *EventChainChecker) HasSniName(name string) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSniName(e, name)
	}
	return e
}

// ProcessChecker checks a process
type ProcessChecker interface {
	// Check checks a process.
	Check(*tetragon.Process, Logger) error
}

// ProcessCheckerFn wraps a function that checks a process
type ProcessCheckerFn func(*tetragon.Process, Logger) error

// Check implements ResponseChecker interface
func (f ProcessCheckerFn) Check(p *tetragon.Process, log Logger) error {
	return f(p, log)
}

// PodChecker checks a Pod
type PodChecker interface {
	// Check checks a Pod
	Check(*tetragon.Pod, Logger) error
}

// PodCheckerFn wraps a function that checks a pod
type PodCheckerFn func(*tetragon.Pod, Logger) error

// Check implements ResponseChecker interface
func (f PodCheckerFn) Check(p *tetragon.Pod, log Logger) error {
	return f(p, log)
}

// ContainerChecker checks a container
type ContainerChecker interface {
	// Check checks a Container
	Check(*tetragon.Container, Logger) error
}

// ContainerCheckerFn wraps a function that checks a container
type ContainerCheckerFn func(*tetragon.Container, Logger) error

// Check implements ResponseChecker interface
func (f ContainerCheckerFn) Check(c *tetragon.Container, log Logger) error {
	return f(c, log)
}

// ImageChecker checks a container image
type ImageChecker interface {
	// Check checks a container image
	Check(*tetragon.Image, Logger) error
}

// ImageCheckerFn wraps a function that checks a container image
type ImageCheckerFn func(*tetragon.Image, Logger) error

// Check implements ResponseChecker interface
func (f ImageCheckerFn) Check(i *tetragon.Image, log Logger) error {
	return f(i, log)
}

// ProcessCheckerAND can be used to build a check that is a conjunction of other checkers
type ProcessCheckerAND struct {
	checks []ProcessChecker
}

// NewProcessChecker creates a new ProcessCheckerAND to verify a series of checks on
// a process
func NewProcessChecker() *ProcessCheckerAND {
	return &ProcessCheckerAND{}
}

// With adds another process checker
func (o *ProcessCheckerAND) With(c ...ProcessChecker) *ProcessCheckerAND {
	o.checks = append(o.checks, c...)
	return o
}

// WithBinary adds a check that the process binary matches the StringArg
func (o *ProcessCheckerAND) WithBinary(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithBinary(sm))
	return o
}

// WithPod adds a check that the process' pod matches the PodChecker
func (o *ProcessCheckerAND) WithPod(arg PodChecker) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithPod(arg))
	return o
}

// WithArguments adds a check that the process' arguments match the StringArg
func (o *ProcessCheckerAND) WithArguments(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithArguments(sm))
	return o
}

// WithCWD adds a check that the process' current working directory matches the StringArg
func (o *ProcessCheckerAND) WithCWD(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithCWD(sm))
	return o
}

// WithDocker adds a check that the process' docker field matches the StringArg
func (o *ProcessCheckerAND) WithDocker(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithDocker(sm))
	return o
}

// WithUID adds a check that the process' UID matches the UID
func (o *ProcessCheckerAND) WithUID(uid uint32) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithUID(uid))
	return o
}

// WithNS adds a check that the process' Ns matches the Ns
func (o *ProcessCheckerAND) WithNs(ns *tetragon.Namespaces) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithNs(ns))
	return o
}

// WithCaps adds a check that the process' Caps matches the Caps
func (o *ProcessCheckerAND) WithCaps(ns *tetragon.Capabilities, ctype int) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithCaps(ns, ctype))
	return o
}

// Check implements ResponseChecker interface
func (o *ProcessCheckerAND) Check(p *tetragon.Process, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(p, l); err != nil {
			return err
		}
	}
	return nil
}

// ProcessCheckerOR can be used to build a check that is a disjunction of other checkers
type ProcessCheckerOR struct {
	checks []ProcessChecker
}

// NewProcessCheckerOr creates a new ProcessCheckerOR to verify at least one of the checks
// on a process
func NewProcessCheckerOr() *ProcessCheckerOR {
	return &ProcessCheckerOR{}
}

// With adds another process checker
func (o *ProcessCheckerOR) With(c ...ProcessChecker) *ProcessCheckerOR {
	o.checks = append(o.checks, c...)
	return o
}

// WithBinary adds a check that the process binary matches the StringArg
func (o *ProcessCheckerOR) WithBinary(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithBinary(sm))
	return o
}

// WithPod adds a check that the process' pod matches the PodChecker
func (o *ProcessCheckerOR) WithPod(arg PodChecker) *ProcessCheckerOR {
	o.checks = append(o.checks, ProcessWithPod(arg))
	return o
}

// WithArguments adds a check that the process' arguments match the StringArg
func (o *ProcessCheckerOR) WithArguments(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithArguments(sm))
	return o
}

// WithCWD adds a check that the process' current working directory matches the StringArg
func (o *ProcessCheckerOR) WithCWD(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithCWD(sm))
	return o
}

// WithDocker adds a check that the process' docker field matches the StringArg
func (o *ProcessCheckerOR) WithDocker(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithDocker(sm))
	return o
}

// WithUID adds a check that the process' UID matches the UID
func (o *ProcessCheckerOR) WithUID(uid uint32) *ProcessCheckerOR {
	o.checks = append(o.checks, ProcessWithUID(uid))
	return o
}

// WithNS adds a check that the process' Ns matches the Ns
func (o *ProcessCheckerOR) WithNs(ns *tetragon.Namespaces) *ProcessCheckerOR {
	o.checks = append(o.checks, ProcessWithNs(ns))
	return o
}

// WithCaps adds a check that the process' Caps matches the Caps
func (o *ProcessCheckerOR) WithCaps(ns *tetragon.Capabilities, ctype int) *ProcessCheckerOR {
	o.checks = append(o.checks, ProcessWithCaps(ns, ctype))
	return o
}

// Check implements ResponseChecker interface
func (o *ProcessCheckerOR) Check(p *tetragon.Process, l Logger) error {
	var failures []error
	for i := range o.checks {
		err := o.checks[i].Check(p, l)
		if err == nil {
			return nil
		}
		failures = append(failures, err)
	}
	return fmt.Errorf("failed to match any checks %v", failures)
}

func processWithString(
	sm StringMatcher,
	getter func(p *tetragon.Process) string,
	desc string, // desc is used for helpful error messages
) ProcessChecker {
	matcher := sm.GetMatcher()
	return ProcessCheckerFn(func(p *tetragon.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(p)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

// ProcessWithCWD matches the cwd field
func ProcessWithCWD(sm StringMatcher) ProcessChecker {
	matcher := sm.GetMatcher()
	return ProcessCheckerFn(func(p *tetragon.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match cwd using %v", sm)
		}
		cwd := p.Cwd
		if strings.Contains(p.Flags, "nocwd") {
			log.Logf("cwd check: nocwd flag set, test considered successful", cwd)
			return nil
		}
		if len(cwd) > 1 && strings.HasSuffix(cwd, "/") {
			cwd = strings.TrimSuffix(cwd, "/")
			log.Logf("cwd check: removed trailing /: cwd=%s", cwd)
		}
		if err := matcher(cwd); err != nil {
			return fmt.Errorf("failed check on %s: %w", "cwd", err)
		}
		log.Logf("**** MATCH on %s: %s", "cwd", p.Cwd)
		return nil
	})
}

// ProcessWithBinary matches the Binary field
func ProcessWithBinary(sm StringMatcher) ProcessChecker {
	return processWithString(
		sm,
		func(p *tetragon.Process) string {
			return p.Binary
		},
		"binary",
	)
}

// ProcessWithArguments matches the Arguments field
func ProcessWithArguments(sm StringMatcher) ProcessChecker {
	return processWithString(
		sm,
		func(p *tetragon.Process) string {
			return p.Arguments
		},
		"arguments",
	)
}

// ProcessWithCommand matches the Binary and Arguments field
func ProcessWithCommand(binary StringMatcher, args StringMatcher) ProcessChecker {
	return &ProcessCheckerAND{
		checks: []ProcessChecker{
			ProcessWithBinary(binary),
			ProcessWithArguments(args),
		},
	}
}

// ProcessWithPod matches the Pod field
func ProcessWithPod(pc PodChecker) ProcessChecker {
	return ProcessCheckerFn(func(p *tetragon.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match pod")
		}
		if err := pc.Check(p.Pod, log); err != nil {
			return fmt.Errorf("failed check on %s: %w", "pod", err)
		}
		return nil
	})
}

// ProcessWithDocker matches the Docker field
func ProcessWithDocker(sm StringMatcher) ProcessChecker {
	return processWithString(
		sm,
		func(p *tetragon.Process) string {
			return p.Docker
		},
		"docker",
	)
}

// ProcessWithUID matches the Uid field
func ProcessWithUID(uid uint32) ProcessChecker {
	return ProcessCheckerFn(func(p *tetragon.Process, log Logger) error {
		if p.Uid == nil {
			return fmt.Errorf("uid %d does not match nil value", uid)
		}
		if p.Uid.Value != uid {
			return fmt.Errorf("uid %d does not match %d value", uid, p.Uid.Value)
		}
		return nil
	})
}

// ProcessWithPID matches the PID field
func ProcessWithPID(pid uint32) ProcessChecker {
	return ProcessCheckerFn(func(p *tetragon.Process, log Logger) error {
		if p.Pid == nil {
			return fmt.Errorf("expected pid %d does not match nil value", pid)
		}
		if p.Pid.Value != pid {
			return fmt.Errorf("expected pid %d does not match %d value", pid, p.Pid.Value)
		}
		return nil
	})
}

func compareNamespace(p *tetragon.Process, ns *tetragon.Namespaces) error {
	if p.Ns == nil {
		return fmt.Errorf("ns %v does not match nil value", ns)
	}
	if (p.Ns.Uts.Inum != ns.Uts.Inum) || (p.Ns.Uts.IsHost != ns.Uts.IsHost) {
		return fmt.Errorf("uts_ns [%d|%t] does not match [%d|%t] value",
			ns.Uts.Inum, ns.Uts.IsHost,
			p.Ns.Uts.Inum, p.Ns.Uts.IsHost)
	}
	if (p.Ns.Ipc.Inum != ns.Ipc.Inum) || (p.Ns.Ipc.IsHost != ns.Ipc.IsHost) {
		return fmt.Errorf("ipc_ns [%d|%t] does not match [%d|%t] value",
			ns.Ipc.Inum, ns.Ipc.IsHost,
			p.Ns.Ipc.Inum, p.Ns.Ipc.IsHost)
	}
	if (p.Ns.Mnt.Inum != ns.Mnt.Inum) || (p.Ns.Mnt.IsHost != ns.Mnt.IsHost) {
		return fmt.Errorf("mnt_ns [%d|%t] does not match [%d|%t] value",
			ns.Mnt.Inum, ns.Mnt.IsHost,
			p.Ns.Mnt.Inum, p.Ns.Mnt.IsHost)
	}
	if (p.Ns.Pid.Inum != ns.Pid.Inum) || (p.Ns.Pid.IsHost != ns.Pid.IsHost) {
		return fmt.Errorf("pid_ns [%d|%t] does not match [%d|%t] value",
			ns.Pid.Inum, ns.Pid.IsHost,
			p.Ns.Pid.Inum, p.Ns.Pid.IsHost)
	}
	if (p.Ns.PidForChildren.Inum != ns.PidForChildren.Inum) || (p.Ns.PidForChildren.IsHost != ns.PidForChildren.IsHost) {
		return fmt.Errorf("pid_for_children_ns [%d|%t] does not match [%d|%t] value",
			ns.PidForChildren.Inum, ns.PidForChildren.IsHost,
			p.Ns.PidForChildren.Inum, p.Ns.PidForChildren.IsHost)
	}
	if (p.Ns.Net.Inum != ns.Net.Inum) || (p.Ns.Net.IsHost != ns.Net.IsHost) {
		return fmt.Errorf("net_ns [%d|%t] does not match [%d|%t] value",
			ns.Net.Inum, ns.Net.IsHost,
			p.Ns.Net.Inum, p.Ns.Net.IsHost)
	}
	if (p.Ns.Time != nil) && ((p.Ns.Time.Inum != ns.Time.Inum) || (p.Ns.Time.IsHost != ns.Time.IsHost)) {
		return fmt.Errorf("time_ns [%d|%t] does not match [%d|%t] value",
			ns.Time.Inum, ns.Time.IsHost,
			p.Ns.Time.Inum, p.Ns.Time.IsHost)
	}
	if (p.Ns.TimeForChildren != nil) && ((p.Ns.TimeForChildren.Inum != ns.TimeForChildren.Inum) || (p.Ns.TimeForChildren.IsHost != ns.TimeForChildren.IsHost)) {
		return fmt.Errorf("time_for_children_ns [%d|%t] does not match [%d|%t] value",
			ns.TimeForChildren.Inum, ns.TimeForChildren.IsHost,
			p.Ns.TimeForChildren.Inum, p.Ns.TimeForChildren.IsHost)
	}
	if (p.Ns.Cgroup.Inum != ns.Cgroup.Inum) || (p.Ns.Cgroup.IsHost != ns.Cgroup.IsHost) {
		return fmt.Errorf("cgroup_ns [%d|%t] does not match [%d|%t] value",
			ns.Cgroup.Inum, ns.Cgroup.IsHost,
			p.Ns.Cgroup.Inum, p.Ns.Cgroup.IsHost)
	}
	if (p.Ns.User.Inum != ns.User.Inum) || (p.Ns.User.IsHost != ns.User.IsHost) {
		return fmt.Errorf("user_ns [%d|%t] does not match [%d|%t] value",
			ns.User.Inum, ns.User.IsHost,
			p.Ns.User.Inum, p.Ns.User.IsHost)
	}
	return nil
}

// ProcessWithNs matches the Namespace field
func ProcessWithNs(ns *tetragon.Namespaces) ProcessChecker {
	return ProcessCheckerFn(func(p *tetragon.Process, log Logger) error {
		return compareNamespace(p, ns)
	})
}

func compareCaps(a []tetragon.CapabilitiesType, b []tetragon.CapabilitiesType, ctype int) error {
	anum := uint64(0)
	for _, idx := range a {
		anum |= (1 << idx)
	}
	bnum := uint64(0)
	for _, idx := range b {
		bnum |= (1 << idx)
	}
	if anum != bnum {
		for i := range tetragon.CapabilitiesType_name {
			if (anum & (1 << i)) != (bnum & (1 << i)) {
				return fmt.Errorf("caps %s does not match %x - %x type: %d", tetragon.CapabilitiesType_name[i], anum, bnum, ctype)
			}
		}
	}
	return nil
}

func compareCapabilities(p *tetragon.Process, caps *tetragon.Capabilities, ctype int) error {
	if p.Cap == nil {
		return fmt.Errorf("caps %v does not match nil value", caps)
	}
	var lCaps []tetragon.CapabilitiesType
	var rCaps []tetragon.CapabilitiesType
	if ctype == CapsPermitted {
		lCaps = caps.GetPermitted()
		rCaps = p.Cap.GetPermitted()
	} else if ctype == CapsEffective {
		lCaps = caps.GetEffective()
		rCaps = p.Cap.GetEffective()
	} else if ctype == CapsInheritable {
		lCaps = caps.GetInheritable()
		rCaps = p.Cap.GetInheritable()
	} else {
		return fmt.Errorf("compareCapabilities: Unknown ctype = %d", ctype)
	}
	if lCaps == nil && rCaps == nil { // both are nil -> accept
		return nil
	}
	return compareCaps(lCaps, rCaps, ctype)
}

// ProcessWithCaps matches the Capabilities field
func ProcessWithCaps(caps *tetragon.Capabilities, ctype int) ProcessChecker {
	return ProcessCheckerFn(func(p *tetragon.Process, log Logger) error {
		return compareCapabilities(p, caps, ctype)
	})
}

// HasProcess adds a check for a process to the event
func (e *EventChainChecker) HasProcess(cs ...ProcessChecker) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		process := eventGetProcess(e)
		if process == nil {
			return fmt.Errorf("process is nil")
		}
		for i := range cs {
			if err := cs[i].Check(process, l); err != nil {
				return fmt.Errorf("process check failed: %w", err)
			}
		}
		return nil
	}
	return e
}

// HasParent adds a check for a parent process to the event
func (e *EventChainChecker) HasParent(cs ...ProcessChecker) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		process := eventGetParent(e)
		if process == nil {
			return fmt.Errorf("parent is nil")
		}
		for i := range cs {
			if err := cs[i].Check(process, l); err != nil {
				return fmt.Errorf("parent check failed: %w", err)
			}
		}
		return nil
	}
	return e
}

// HasAncestor adds a check for an ancestor process `idx` processes back to the event
// chain, where idx=0 would be the parent process
func (e *EventChainChecker) HasAncestor(idx int, cs ...ProcessChecker) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		ev, ok := e.(interface{ GetAncestors() []*tetragon.Process })
		if !ok {
			return fmt.Errorf("type %T does not have ancestors", e)
		}

		ancestors := ev.GetAncestors()
		if idx < 0 || len(ancestors) <= idx {
			return fmt.Errorf("event has %d ancestors: index %d is invalid", len(ancestors), idx)
		}

		process := ancestors[idx]
		if process == nil {
			return fmt.Errorf("ancestor idx=%d is nil", idx)
		}
		for i := range cs {
			if err := cs[i].Check(process, l); err != nil {
				return fmt.Errorf("ancestor check failed: %w", err)
			}
		}
		return nil
	}
	return e
}

// PodCheckerAND can be used to build a check that is a conjunction of other checkers
type PodCheckerAND struct {
	checks []PodChecker
}

// NewPodChecker creates a new PodCheckerAND to verify all checks on a given Pod
func NewPodChecker() *PodCheckerAND {
	return &PodCheckerAND{}
}

// Check implements ResponseChecker interface
func (o *PodCheckerAND) Check(p *tetragon.Pod, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(p, l); err != nil {
			return err
		}
	}
	return nil
}

func podWithString(
	sm StringMatcher,
	getter func(p *tetragon.Pod) string,
	desc string, // desc is used for helpful error messages
) PodChecker {
	matcher := sm.GetMatcher()
	return PodCheckerFn(func(p *tetragon.Pod, log Logger) error {
		if p == nil {
			return fmt.Errorf("pod is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(p)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

// PodWithName verifies the Name field
func PodWithName(sm StringMatcher) PodChecker {
	return podWithString(
		sm,
		func(p *tetragon.Pod) string {
			return p.Name
		},
		"pod-name",
	)
}

// PodWithNamespace verifies the Namespace field
func PodWithNamespace(sm StringMatcher) PodChecker {
	return podWithString(
		sm,
		func(p *tetragon.Pod) string {
			return p.Namespace
		},
		"pod-namespace",
	)
}

// WithName adds a check that verifies the pod's name
func (o *PodCheckerAND) WithName(arg StringArg) *PodCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, PodWithName(sm))
	return o
}

// WithNamePrefix adds a check that verifies the pod's name matches a prefix
func (o *PodCheckerAND) WithNamePrefix(prefix string) *PodCheckerAND {
	sm := PrefixStringMatch(prefix)
	o.checks = append(o.checks, PodWithName(sm))
	return o
}

// WithNamespace adds a check that verifies the pod's namespace
func (o *PodCheckerAND) WithNamespace(arg StringArg) *PodCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, PodWithNamespace(sm))
	return o
}

// PodWithLabels verifies the Labels field.
// N.B. that this currently matches _all_ labels in order.
func PodWithLabels(labels ...LabelMatch) PodChecker {
	labelMatchers := make(map[string]func(string) error)
	for i := range labels {
		labelMatchers[labels[i].Key] = labels[i].Val.GetMatcher()
	}

	// build a warning that we can pass to the closure below and inform the
	// user that something might be wrong
	warn := ""
	if len(labelMatchers) != len(labels) {
		warn = fmt.Sprintf("Warning: WithLabels() argument %+v has colliding keys", labels)
	}

	return PodCheckerFn(func(p *tetragon.Pod, l Logger) error {
		if warn != "" {
			l.Logf(warn)
		}
		matchedLabels := map[string]struct{}{}
		for _, label := range p.Labels {
			kv := strings.SplitN(label, "=", 2)
			if len(kv) != 2 {
				l.Logf("label %s does not match key=val format. Ignoring", label)
				continue
			}
			key := kv[0]
			val := kv[1]
			if matcher, ok := labelMatchers[key]; ok {
				if err := matcher(val); err != nil {
					return fmt.Errorf("label %s mismatch: %w", key, err)
				}
			}
			matchedLabels[key] = struct{}{}
		}

		if len(matchedLabels) != len(labelMatchers) {
			unMatchedLabels := []string{}
			for k := range labelMatchers {
				if _, ok := matchedLabels[k]; !ok {
					unMatchedLabels = append(unMatchedLabels, k)
				}
			}
			if len(unMatchedLabels) > 0 {
				return fmt.Errorf("unmatched labels: %+v", unMatchedLabels)
			}
		}

		l.Logf("**** MATCH on %s: %s", "labels", p.Labels)
		return nil
	})
}

// WithLabels will try and match all the given labels. Specifically, it will
// check that the argument labels are a _subset_ of the pod labels.
func (o *PodCheckerAND) WithLabels(labels ...LabelMatch) *PodCheckerAND {
	o.checks = append(o.checks, PodWithLabels(labels...))
	return o
}

// ContainerCheckerAND can be used to build a check that is a conjunction of other checkers
type ContainerCheckerAND struct {
	checks []ContainerChecker
}

// NewContainerChecker creates a new ContainerCheckerAND to verify a series of checks on
// a container
func NewContainerChecker() *ContainerCheckerAND {
	return &ContainerCheckerAND{}
}

// Check implements ResponseChecker interface
func (o *ContainerCheckerAND) Check(p *tetragon.Container, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(p, l); err != nil {
			return err
		}
	}
	return nil
}

// PodWithContainer verifies that a pod's container matches a series of container checks
func PodWithContainer(cc ContainerChecker) PodChecker {
	return PodCheckerFn(func(p *tetragon.Pod, log Logger) error {
		if p == nil {
			return fmt.Errorf("pod is nil and cannot match container")
		}
		if err := cc.Check(p.Container, log); err != nil {
			return fmt.Errorf("failed check on %s: %w", "container", err)
		}
		return nil
	})
}

// WithContainer adds a check to verify that a pod's container passes a ContainerChecker
func (o *PodCheckerAND) WithContainer(arg ContainerChecker) *PodCheckerAND {
	o.checks = append(o.checks, PodWithContainer(arg))
	return o
}

func containerWithString(
	sm StringMatcher,
	getter func(p *tetragon.Container) string,
	desc string, // desc is used for helpful error messages
) ContainerChecker {
	matcher := sm.GetMatcher()
	return ContainerCheckerFn(func(c *tetragon.Container, log Logger) error {
		if c == nil {
			return fmt.Errorf("container is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(c)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

// ContainerWithName verifies the Name field
func ContainerWithName(sm StringMatcher) ContainerChecker {
	return containerWithString(
		sm,
		func(c *tetragon.Container) string {
			return c.Name
		},
		"container-name",
	)
}

// WithName adds a check that verifies the Name field
func (o *ContainerCheckerAND) WithName(arg StringArg) *ContainerCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ContainerWithName(sm))
	return o
}

// WithNamePrefix adds a check that verifies the Name field matches a prefix
func (o *ContainerCheckerAND) WithNamePrefix(prefix string) *ContainerCheckerAND {
	sm := PrefixStringMatch(prefix)
	o.checks = append(o.checks, ContainerWithName(sm))
	return o
}

// ContainerWithID verifies the Id field
func ContainerWithID(sm StringMatcher) ContainerChecker {
	return containerWithString(
		sm,
		func(c *tetragon.Container) string {
			return c.Id
		},
		"container-id",
	)
}

// ContainerWithImageName verifies the ImageName field
func ContainerWithImageName(sm StringMatcher) ContainerChecker {
	matcher := sm.GetMatcher()
	return ContainerCheckerFn(func(c *tetragon.Container, log Logger) error {
		desc := "container-image-name"
		if c == nil {
			return fmt.Errorf("container is nil and cannot match %s using %v", desc, sm)
		}
		if c.Image == nil {
			return fmt.Errorf("container is nil and cannot match %s using %v", desc, sm)
		}
		s := c.Image.Name
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

// WithImageName adds a check that verifies the ImageName field
func (o *ContainerCheckerAND) WithImageName(arg StringArg) *ContainerCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ContainerWithImageName(sm))
	return o
}

// DNSChecker checks the DNS field of an DNS event
type DNSChecker interface {
	// Check checks a DNS event
	Check(*tetragon.ProcessDns, Logger) error
}

// DNSCheckerFn wraps a function that checks the DNS field of an DNS event
type DNSCheckerFn func(*tetragon.ProcessDns, Logger) error

// Check implements ResponseChecker interface
func (f DNSCheckerFn) Check(c *tetragon.ProcessDns, log Logger) error {
	return f(c, log)
}

func dnsWithString(
	sm StringMatcher,
	getter func(*tetragon.ProcessDns) string,
	desc string, // desc is used for helpful error messages
) DNSChecker {
	matcher := sm.GetMatcher()
	return DNSCheckerFn(func(t *tetragon.ProcessDns, log Logger) error {
		if t == nil {
			return fmt.Errorf("DNS is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(t)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed DNS check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH DNS on %s: %s", desc, s)
		return nil
	})
}

// DNSIsResponse checks whether a Dns event is a response
func DNSIsResponse(isResponse bool) DNSChecker {
	return DNSCheckerFn(func(t *tetragon.ProcessDns, log Logger) error {
		if t == nil {
			return fmt.Errorf("DNS is nil and cannot match Response: %t", isResponse)
		}
		if t.Dns.Response != isResponse {
			return fmt.Errorf("expecting DNS Response to be %t but got %t", isResponse, t.Dns.Response)
		}
		log.Logf("**** MATCH DNS on Response: %t", t.Dns.Response)
		return nil
	})
}

// DNSHasRcode checks the Rcode field
func DNSHasRcode(rcode int32) DNSChecker {
	return DNSCheckerFn(func(t *tetragon.ProcessDns, log Logger) error {
		if t == nil {
			return fmt.Errorf("DNS is nil and cannot match Rcode: %d", rcode)
		}
		if t.Dns.Rcode != rcode {
			return fmt.Errorf("expecting Dns Rcode to be %d but got %d", rcode, t.Dns.Rcode)
		}
		log.Logf("**** MATCH DNS on Rcode: %t", t.Dns.Rcode)
		return nil
	})
}

// DNSHasQuery checks the Query field
func DNSHasQuery(sm StringMatcher) DNSChecker {
	return dnsWithString(
		sm,
		func(t *tetragon.ProcessDns) string {
			return t.Dns.Query
		},
		"Query",
	)
}

// DNSHasAnswerTypes checks a specific set of answer types.
// N.B. This check is order-preserving and expects a full match.
func DNSHasAnswerTypes(answerTypes []uint32) DNSChecker {
	return DNSCheckerFn(func(t *tetragon.ProcessDns, log Logger) error {
		if t == nil {
			return fmt.Errorf("DNS is nil and cannot match AnswerTypes: %+v", answerTypes)
		}
		if !reflect.DeepEqual(t.Dns.AnswerTypes, answerTypes) {
			return fmt.Errorf("expecting DNS AnswerTypes to be %+v but got %+v", answerTypes, t.Dns.AnswerTypes)
		}
		log.Logf("**** MATCH DNS on AnswerTypes: %+v", t.Dns.AnswerTypes)
		return nil
	})
}

// DNSHasQuestionTypes checks a specific set of question types.
// N.B. This check is order-preserving and expects a full match.
func DNSHasQuestionTypes(questionTypes []uint32) DNSChecker {
	return DNSCheckerFn(func(t *tetragon.ProcessDns, log Logger) error {
		if t == nil {
			return fmt.Errorf("DNS is nil and cannot match QuestionTypes: %+v", questionTypes)
		}
		if !reflect.DeepEqual(t.Dns.QuestionTypes, questionTypes) {
			return fmt.Errorf("expecting DNs QuestionTypes to be %+v but got %+v", questionTypes, t.Dns.QuestionTypes)
		}
		log.Logf("**** MATCH DNS on QuestionTypes: %+v", t.Dns.QuestionTypes)
		return nil
	})
}

// DNSHasNames checks a specific set of names.
// N.B. This check is order-preserving and expects a full match.
func DNSHasNames(matchers []StringMatcher) DNSChecker {
	return DNSCheckerFn(func(t *tetragon.ProcessDns, log Logger) error {
		if t == nil {
			return fmt.Errorf("DNS is nil and cannot match Names: %+v", matchers)
		}
		for i := range t.Dns.Names {
			matcher := matchers[i].GetMatcher()
			name := t.Dns.Names[i]
			if err := matcher(name); err != nil {
				return fmt.Errorf("failed check on name %s (idx=%d): %w", name, i, err)
			}
		}
		log.Logf("**** MATCH DNS on Names: %s", t.Dns.Names)
		return nil
	})
}

// DNSHasIPs checks a specific set of names.
// N.B. This check is order-preserving and expects a full match.
func DNSHasIPs(matchers []StringMatcher) DNSChecker {
	return DNSCheckerFn(func(t *tetragon.ProcessDns, log Logger) error {
		if t == nil {
			return fmt.Errorf("DNS is nil and cannot match IPs: %+v", matchers)
		}
		for i := range t.Dns.Ips {
			matcher := matchers[i].GetMatcher()
			ip := t.Dns.Ips[i]
			if err := matcher(ip); err != nil {
				return fmt.Errorf("failed check on IP %s (idx=%d): %w", ip, i, err)
			}
		}
		log.Logf("**** MATCH DNS on IPs: %s", t.Dns.Ips)
		return nil
	})
}

// DNSCheckerAND can be used to build a check that is a conjunction of other checkers
type DNSCheckerAND struct {
	checks []DNSChecker
}

// NewDNSChecker creates a new DNSCheckerAND to verify a series of checks on
// a DNS event
func NewDNSChecker() *DNSCheckerAND {
	return &DNSCheckerAND{}
}

// Check implements ResponseChecker interface
func (o *DNSCheckerAND) Check(t *tetragon.ProcessDns, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(t, l); err != nil {
			return err
		}
	}
	return nil
}

// IsResponse adds a DNS.Response check to a DNS checker
func (o *DNSCheckerAND) IsResponse(isResponse bool) *DNSCheckerAND {
	o.checks = append(o.checks, DNSIsResponse(isResponse))
	return o
}

// WithRcode adds a DNS.Rcode check to a DNS checker
func (o *DNSCheckerAND) WithRcode(rcode int32) *DNSCheckerAND {
	o.checks = append(o.checks, DNSHasRcode(rcode))
	return o
}

// WithQuery adds a DNS.Query check to a DNS checker
func (o *DNSCheckerAND) WithQuery(query StringArg) *DNSCheckerAND {
	sm := stringMatcherFromArg(query)
	o.checks = append(o.checks, DNSHasQuery(sm))
	return o
}

// WithAnswerTypes adds a DNS.AnswerTypes check to a DNS checker
func (o *DNSCheckerAND) WithAnswerTypes(answerTypes []uint32) *DNSCheckerAND {
	o.checks = append(o.checks, DNSHasAnswerTypes(answerTypes))
	return o
}

// WithQuestionTypes adds a DNS.QuestionTypes check to a DNS checker
func (o *DNSCheckerAND) WithQuestionTypes(questionTypes []uint32) *DNSCheckerAND {
	o.checks = append(o.checks, DNSHasQuestionTypes(questionTypes))
	return o
}

// WithIps adds a DNS.Ips check to a DNS checker
func (o *DNSCheckerAND) WithIps(ips []StringArg) *DNSCheckerAND {
	matchers := make([]StringMatcher, len(ips))
	for i := range matchers {
		matchers[i] = stringMatcherFromArg(ips[i])
	}
	o.checks = append(o.checks, DNSHasIPs(matchers))
	return o
}

// WithNames adds a Dns.Names check to a Dns checker
func (o *DNSCheckerAND) WithNames(names []StringArg) *DNSCheckerAND {
	matchers := make([]StringMatcher, len(names))
	for i := range matchers {
		matchers[i] = stringMatcherFromArg(names[i])
	}
	o.checks = append(o.checks, DNSHasNames(matchers))
	return o
}

// HasDNS adds a check for a TLS field to the TLS event
func (e *EventChainChecker) HasDNS(dnscheck DNSChecker) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		if dnsEv, ok := e.(*tetragon.ProcessDns); ok {
			return dnscheck.Check(dnsEv, l)
		}
		return fmt.Errorf("event has type %T: not a dns event", e)

	}
	return e
}

// TracepointChecker checks a the tracepoint field of a tracepoint event
type TracepointChecker interface {
	// Check checks a Tracepoint event
	Check(*tetragon.ProcessTracepoint, Logger) error
}

// TracepointCheckerFn wraps a function that checks the tracepoint field of an tracepoint event
type TracepointCheckerFn func(*tetragon.ProcessTracepoint, Logger) error

// Check implements ResponseChecker interface
func (f TracepointCheckerFn) Check(c *tetragon.ProcessTracepoint, log Logger) error {
	return f(c, log)
}

// TracepointCheckerAND can be used to build a check that is a conjunction of other checkers
type TracepointCheckerAND struct {
	checks []TracepointChecker
}

// Check implements ResponseChecker interface
func (o *TracepointCheckerAND) Check(t *tetragon.ProcessTracepoint, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(t, l); err != nil {
			return err
		}
	}
	return nil
}

// NewTracepointChecker creates a new TracepointCheckerAND to verify a series of checks on
// a tracepoint event
func NewTracepointChecker() *TracepointCheckerAND {
	return &TracepointCheckerAND{}
}

// WithSubsys adds a subystem check
func (o *TracepointCheckerAND) WithSubsys(arg StringArg) *TracepointCheckerAND {
	sm := stringMatcherFromArg(arg)
	matcher := sm.GetMatcher()
	check := TracepointCheckerFn(func(t *tetragon.ProcessTracepoint, log Logger) error {
		if err := matcher(t.Subsys); err != nil {
			return fmt.Errorf("failed check on subsys: %w", err)
		}
		log.Logf("**** MATCH tracepoint subsys: %s", t.Subsys)
		return nil
	})
	o.checks = append(o.checks, check)
	return o
}

// WithEvent adds an event check
func (o *TracepointCheckerAND) WithEvent(arg StringArg) *TracepointCheckerAND {
	sm := stringMatcherFromArg(arg)
	matcher := sm.GetMatcher()
	check := TracepointCheckerFn(func(t *tetragon.ProcessTracepoint, log Logger) error {
		if err := matcher(t.Event); err != nil {
			return fmt.Errorf("failed check on event: %w", err)
		}
		log.Logf("**** MATCH tracepoint event: %s", t.Event)
		return nil
	})
	o.checks = append(o.checks, check)
	return o
}

// TracepointWithArgs matches the Args field
// NB: eventually we might want other type of matches for matching a list such
// as subset checks, but for now we check that the elemnts of the lists match
// one-by-one.
func TracepointWithArgs(checkers []GenericArgChecker) TracepointChecker {
	return TracepointCheckerFn(func(t *tetragon.ProcessTracepoint, log Logger) error {
		if t == nil {
			return fmt.Errorf("tracepoint is nil and cannot match checkers: %+v", checkers)
		}

		if len(t.Args) != len(checkers) {
			return fmt.Errorf("failed to match tracepoint args of length %d to checkers: %+v", len(t.Args), checkers)
		}

		for i := range t.Args {
			checkArg := checkers[i]
			arg := t.Args[i]
			if err := checkArg.Check(arg, log); err != nil {
				return fmt.Errorf("failed check arg %s (idx=%d): %w", arg, i, err)
			}
		}

		log.Logf("**** MATCH tracepoint args: %s", t.Args)
		return nil
	})
}

// WithArgs adds a check on the tracepoint args
func (o *TracepointCheckerAND) WithArgs(argCheckers []GenericArgChecker) *TracepointCheckerAND {
	o.checks = append(o.checks, TracepointWithArgs(argCheckers))
	return o
}

// NewTracepointEventChecker creates a new EventChainChecker for tracepoint events
func NewTracepointEventChecker() *EventChainChecker {
	return &EventChainChecker{
		responseCheck: func(r *tetragon.GetEventsResponse, l Logger) (tetragonEvent, error) {
			return checkEvent(r, l, tetragon.EventType_PROCESS_TRACEPOINT)
		},
		eventCheck: func(ev tetragonEvent, l Logger) error {
			return nil
		},
	}
}

// HasTracepoint adds a check for a tracepoint field to the tracepoint event
func (e *EventChainChecker) HasTracepoint(tpCheck TracepointChecker) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		if tpEv, ok := e.(*tetragon.ProcessTracepoint); ok {
			return tpCheck.Check(tpEv, l)
		}
		return fmt.Errorf("event has type %T: not a tracepoint event", e)

	}
	return e
}

// KprobeChecker checks a the tracepoint field of a kprobe event
type KprobeChecker interface {
	// Check checks a generic kprobe event
	Check(*tetragon.ProcessKprobe, Logger) error
}

// KprobeCheckerFn wraps a function that checks the kprobe field of an kprobe event
type KprobeCheckerFn func(*tetragon.ProcessKprobe, Logger) error

// Check implements ResponseChecker interface
func (f KprobeCheckerFn) Check(c *tetragon.ProcessKprobe, log Logger) error {
	return f(c, log)
}

// KprobeCheckerAND can be used to build a check that is a conjunction of other checkers
type KprobeCheckerAND struct {
	checks []KprobeChecker
}

// Check implements ResponseChecker interface
func (o *KprobeCheckerAND) Check(t *tetragon.ProcessKprobe, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(t, l); err != nil {
			return err
		}
	}
	return nil
}

// NewKprobeChecker creates a new KprobeCheckerAND to verify a series of checks on
// a kprobe event
func NewKprobeChecker() *KprobeCheckerAND {
	return &KprobeCheckerAND{}
}

// WithFunctionName adds a function name check
func (o *KprobeCheckerAND) WithFunctionName(arg StringArg) *KprobeCheckerAND {
	sm := stringMatcherFromArg(arg)
	matcher := sm.GetMatcher()
	check := KprobeCheckerFn(func(t *tetragon.ProcessKprobe, log Logger) error {
		if err := matcher(t.FunctionName); err != nil {
			return fmt.Errorf("failed check on function name: %w", err)
		}
		log.Logf("**** MATCH kprobe function name: %s", t.FunctionName)
		return nil
	})
	o.checks = append(o.checks, check)
	return o
}

func KprobeWithAction(act tetragon.KprobeAction) KprobeChecker {
	actString := tetragon.KprobeAction_name[int32(act)]
	return KprobeCheckerFn(func(k *tetragon.ProcessKprobe, log Logger) error {
		if k == nil {
			return fmt.Errorf("kprobe is nil and cannot match action: %+v", act)
		}
		kact := k.GetAction()
		kactString := tetragon.KprobeAction_name[int32(kact)]
		if kact != act {
			return fmt.Errorf("failed to match kprobe action %d (%s) to %d (%s)",
				kact, kactString, act, actString)
		}
		log.Logf("**** MATCH kprobe action: %d (%s)", act, actString)
		return nil
	})
}

// WithArgs adds a checker on the kprobe args
func (o *KprobeCheckerAND) WithAction(act tetragon.KprobeAction) *KprobeCheckerAND {
	o.checks = append(o.checks, KprobeWithAction(act))
	return o
}

// withNs add namespaces check
func (o *KprobeCheckerAND) WithNs(ns *tetragon.Namespaces) *KprobeCheckerAND {
	check := KprobeCheckerFn(func(t *tetragon.ProcessKprobe, log Logger) error {
		ret := compareNamespace(t.Process, ns)
		if ret == nil {
			log.Logf("**** MATCH kprobe namespace")
		}
		return ret
	})
	o.checks = append(o.checks, check)
	return o
}

// withCaps add capabilities check
func (o *KprobeCheckerAND) WithCaps(caps *tetragon.Capabilities, ctype int) *KprobeCheckerAND {
	check := KprobeCheckerFn(func(t *tetragon.ProcessKprobe, log Logger) error {
		ret := compareCapabilities(t.Process, caps, ctype)
		if ret == nil {
			log.Logf("**** MATCH kprobe capabilities")
		}
		return ret
	})
	o.checks = append(o.checks, check)
	return o
}

func compareKprobeArgs(checkers []GenericArgChecker, k *tetragon.ProcessKprobe, log Logger) error {
	if len(k.Args) != len(checkers) {
		return fmt.Errorf("failed to match kprobe args of length %d to checkers: %+v", len(k.Args), checkers)
	}

	for i := range k.Args {
		checkArg := checkers[i]
		arg := k.Args[i]
		if err := checkArg.Check(arg, log); err != nil {
			return fmt.Errorf("failed check arg %s (idx=%d): %w", arg, i, err)
		}
	}
	return nil
}

// KprobeWithArgs matches the Args field
// NB: eventually we might want other type of matches for matching a list such
// as subset checks, but for now we check that the elemnts of the lists match
// one-by-one.
func KprobeWithArgs(checkers []GenericArgChecker) KprobeChecker {
	return KprobeCheckerFn(func(k *tetragon.ProcessKprobe, log Logger) error {
		if k == nil {
			return fmt.Errorf("kprobe is nil and cannot match checkers: %+v", checkers)
		}

		if err := compareKprobeArgs(checkers, k, log); err != nil {
			return err
		}

		log.Logf("**** MATCH kprobe args: %s", k.Args)
		return nil
	})
}

// WithArgs adds a checker on the kprobe args
func (o *KprobeCheckerAND) WithArgs(argCheckers []GenericArgChecker) *KprobeCheckerAND {
	o.checks = append(o.checks, KprobeWithArgs(argCheckers))
	return o
}

// KprobeWithArgsReturn matches the Args field together with return value
func KprobeWithArgsReturn(checkers []GenericArgChecker, retChecker GenericArgChecker) KprobeChecker {
	return KprobeCheckerFn(func(k *tetragon.ProcessKprobe, log Logger) error {
		if k == nil {
			return fmt.Errorf("kprobe is nil and cannot match checkers: %+v", checkers)
		}

		if err := compareKprobeArgs(checkers, k, log); err != nil {
			return err
		}

		if err := retChecker.Check(k.Return, log); err != nil {
			return fmt.Errorf("failed check return value %s: %w", k.Return, err)
		}

		log.Logf("**** MATCH kprobe args: %s, return: %s", k.Args, k.Return)
		return nil
	})
}

// WithArgsReturn adds a checker on the kprobe args together with return value
func (o *KprobeCheckerAND) WithArgsReturn(argCheckers []GenericArgChecker, retChecker GenericArgChecker) *KprobeCheckerAND {
	o.checks = append(o.checks, KprobeWithArgsReturn(argCheckers, retChecker))
	return o
}

// NewKprobeEventChecker creates a new EventChainChecker for tracepoint events
func NewKprobeEventChecker() *EventChainChecker {
	return &EventChainChecker{
		responseCheck: func(r *tetragon.GetEventsResponse, l Logger) (tetragonEvent, error) {
			return checkEvent(r, l, tetragon.EventType_PROCESS_KPROBE)
		},
		eventCheck: func(ev tetragonEvent, l Logger) error {
			return nil
		},
	}
}

// HasKprobe adds a check for a kprobe field to the kprobe event
func (e *EventChainChecker) HasKprobe(kpCheck KprobeChecker) *EventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e tetragonEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		if kpEv, ok := e.(*tetragon.ProcessKprobe); ok {
			return kpCheck.Check(kpEv, l)
		}
		return fmt.Errorf("event has type %T: not a kprobe event", e)

	}
	return e
}

// GenericArgChecker checks a generic argument
type GenericArgChecker interface {
	// Check checks a generic argument
	Check(*tetragon.KprobeArgument, Logger) error
}

// GenericArgCheckerFn wraps a function that checks a generic argument
type GenericArgCheckerFn func(*tetragon.KprobeArgument, Logger) error

// Check implements ResponseChecker interface
func (f GenericArgCheckerFn) Check(c *tetragon.KprobeArgument, log Logger) error {
	return f(c, log)
}

// GenericArgSizeCheck checks the size of a generic arg
func GenericArgSizeCheck(val uint64) GenericArgChecker {
	return GenericArgCheckerFn(func(arg *tetragon.KprobeArgument, log Logger) error {
		if sa, ok := arg.Arg.(*tetragon.KprobeArgument_SizeArg); ok {
			if sa.SizeArg != val {
				return fmt.Errorf("failed size arg check: %d does not match %d", sa.SizeArg, val)
			}
			log.Logf("**** MATCH generic size arg with value %d", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a size arg", arg.Arg)
	})
}

// GenericArgIsInt checks that a generic arg is an integer
func GenericArgIsInt() GenericArgChecker {
	return GenericArgCheckerFn(func(arg *tetragon.KprobeArgument, log Logger) error {
		if _, ok := arg.Arg.(*tetragon.KprobeArgument_IntArg); ok {
			log.Logf("**** MATCH generic int arg")
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not an int arg", arg.Arg)
	})
}

// GenericArgIntCheck checks the value of an integer arg
func GenericArgIntCheck(val int32) GenericArgChecker {
	return GenericArgCheckerFn(func(arg *tetragon.KprobeArgument, log Logger) error {
		if ia, ok := arg.Arg.(*tetragon.KprobeArgument_IntArg); ok {
			if ia.IntArg != val {
				return fmt.Errorf("failed int arg check: %d does not match %d", ia.IntArg, val)
			}
			log.Logf("**** MATCH generic int arg with value %d", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not an int arg", arg.Arg)
	})
}

// GenericArgBytesCheck checks the value of a bytes arg
func GenericArgBytesCheck(val []byte) GenericArgChecker {
	return GenericArgCheckerFn(func(arg *tetragon.KprobeArgument, log Logger) error {
		if ba, ok := arg.Arg.(*tetragon.KprobeArgument_BytesArg); ok {
			if len(ba.BytesArg) != len(val) {
				return fmt.Errorf("failed bytes arg check: length %d does not match length %d", len(ba.BytesArg), len(val))
			}
			for xi, xb := range ba.BytesArg {
				if xb != val[xi] {
					return fmt.Errorf("failed bytes arg check: byte %d is %x and does not match %x", xi, xb, val[xi])
				}
			}
			log.Logf("**** MATCH generic bytes arg with value %s", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a bytes arg", arg.Arg)
	})
}

// GenericArgStringCheck checks the value of a string arg
func GenericArgStringCheck(val StringArg) GenericArgChecker {
	sm := stringMatcherFromArg(val)
	matcher := sm.GetMatcher()
	return GenericArgCheckerFn(func(arg *tetragon.KprobeArgument, log Logger) error {
		if sa, ok := arg.Arg.(*tetragon.KprobeArgument_StringArg); ok {
			if err := matcher(sa.StringArg); err != nil {
				return fmt.Errorf("failed string arg check: %w", err)
			}
			log.Logf("**** MATCH generic string arg with value %s", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a string arg", arg.Arg)
	})
}

// GenericArgFileChecker checks the value of a file arg
func GenericArgFileChecker(mount, path, flags StringArg) GenericArgChecker {
	smMount := stringMatcherFromArg(mount)
	smPath := stringMatcherFromArg(path)
	smFlags := stringMatcherFromArg(flags)
	matcherMount := smMount.GetMatcher()
	matcherPath := smPath.GetMatcher()
	matcherFlags := smFlags.GetMatcher()
	return GenericArgCheckerFn(func(arg *tetragon.KprobeArgument, log Logger) error {
		if fa, ok := arg.Arg.(*tetragon.KprobeArgument_FileArg); ok {
			if fa.FileArg == nil {
				return fmt.Errorf("failed file arg check because FileArg is nil")
			}
			if err := matcherMount(fa.FileArg.Mount); err != nil {
				return fmt.Errorf("failed file arg check on mountpoint: %w", err)
			}
			if err := matcherPath(fa.FileArg.Path); err != nil {
				return fmt.Errorf("failed file arg check on path: %w", err)
			}
			if err := matcherFlags(fa.FileArg.Flags); err != nil {
				return fmt.Errorf("failed file arg check on flags: %w", err)
			}
			log.Logf("**** MATCH generic file arg: %+v", fa.FileArg)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a file arg", arg.Arg)
	})
}
