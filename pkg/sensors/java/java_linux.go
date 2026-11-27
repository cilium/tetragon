// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

// Package java implements the java sensor, which monitors java method calls
// with the jvmti agent loaded into the JVMs.
//
// The sensor is created for tracing policy with the java section and does
// following for it:
//
//   - translates the policy hooks into the agent hooks (PolicyHandler)
//   - starts the agent control server, one for all java policies, and
//     passes the policy to it (Load)
//   - scans /proc every second for JVMs matching the policy targets (scan)
//   - authorizes each matching JVM on the control server and loads the
//     agent into it (attach)
//
// The agent connects to the control server, gets the hooks of the policies
// its JVM is authorized for and reports the hooked method calls, which the
// sensor submits as java events (ensureServer).
//
// The agent stays loaded in the JVM when the policy is removed or Tetragon
// exits, and connects back to the new Tetragon instance on its own.
package java

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	grpctracing "github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/javaagent"
	"github.com/cilium/tetragon/pkg/javaattach"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	sensorName = "java"

	// installedNativeAgentPath is where 'make install' and the container
	// image put the agent library.
	installedNativeAgentPath = "/usr/lib/tetragon/tetragon-jvmti.so"

	// sourceNativeAgentPath is the agent library built in the source
	// tree, relative to the working directory.
	sourceNativeAgentPath = "pkg/javaattach/agent/tetragon-jvmti.so"

	// scanInterval is how often the sensor looks for new JVMs in /proc.
	scanInterval = time.Second

	// retryInterval is the minimal time between two attach attempts to
	// the same JVM.
	retryInterval = 5 * time.Second

	// reconnectGrace is how long the sensor waits for an agent that is
	// already loaded in the JVM to connect back, before it attaches to
	// the JVM again. The agent retries at least every 5 seconds.
	reconnectGrace = 10 * time.Second

	// agentFilePrefix starts the name of the agent library copy under
	// /tmp of the JVM.
	agentFilePrefix = ".tetragon-jvmti-"
)

// policyHandler creates the java sensor for tracing policy with the java
// section.
type policyHandler struct{}

// processIdentity identifies the process. The pid alone is not enough,
// because it gets reused, so it comes with the process start time (in clock
// ticks since boot, from /proc/<pid>/stat).
type processIdentity struct {
	pid        int
	startTicks uint64
}

// javaSensor is the sensor of one java tracing policy.
type javaSensor struct {
	*sensors.Sensor

	// mu protects the sensor state below and the Loaded and Destroyed
	// flags of the Sensor.
	mu sync.Mutex

	// policy is the policy in the form the agent control server takes,
	// it has the agent hooks and the metadata for their events.
	policy javaagent.Policy

	// agentPath is the agent library that is loaded into the JVMs.
	agentPath string

	// agentEnabled is set when the policy has hooks. Without hooks there
	// is nothing for the agent to do and the sensor stays idle.
	agentEnabled bool

	// executables and argsContain are the policy targets, they select
	// the JVMs the policy applies to, see matchingProcesses.
	executables map[string]struct{}
	argsContain []string

	// active holds JVMs that have the agent and are authorized for the
	// policy, by pid. Each of them holds one reference in attachedVMs.
	active map[int]processIdentity

	// lastAttempt is the time of the last attach attempt to the JVM, by
	// pid, used to keep retryInterval between the attempts.
	lastAttempt map[int]time.Time

	// waiting holds JVMs that have the agent loaded by previous Tetragon
	// instance and the time the sensor started to wait for it to connect
	waiting map[processIdentity]time.Time

	// stop is closed by Unload to stop the watch goroutine, which closes
	// done when it is finished.
	stop chan struct{}
	done chan struct{}
}

var (
	// agentServer is the agent control server shared by all java
	// sensors, started by the first ensureServer call.
	serverOnce  sync.Once
	agentServer *javaagent.Server

	// attachedVMs holds JVMs that have the agent, with the number of
	// sensors (policies) that use it. The JVM is attached just once,
	// following policies only take reference.
	//
	// It is protected by attachedMu, which is taken inside the sensor
	// mutex. It is held also during the attach, so sensors do not attach
	// to the same JVM at the same time.
	attachedMu  sync.Mutex
	attachedVMs = make(map[processIdentity]int)
)

func init() {
	sensors.RegisterPolicyHandlerAtInit(sensorName, policyHandler{})
}

// ensureServer returns the agent control server, the first call creates it
// and starts to listen on the control socket.
//
// The server calls the callback for each hooked method call reported by
// the agents, we submit it to the observer as MsgJavaEvent, which ends up
// as ProcessJava event.
func ensureServer() *javaagent.Server {
	serverOnce.Do(func() {
		path := optionSocketPath()

		agentServer = javaagent.NewServer(path, func(
			pid, tid uint32,
			ktime, methodID uint64,
			className, methodName, descriptor, policyName, message string,
			tags []string,
		) {
			observer.SubmitEvent(&grpctracing.MsgJavaEvent{
				Pid:        pid,
				Tid:        tid,
				Ktime:      ktime,
				MethodID:   methodID,
				ClassName:  className,
				MethodName: methodName,
				Descriptor: descriptor,
				PolicyName: policyName,
				Message:    message,
				Tags:       tags,
			})
		})

		// The option is not set in tests, the server has its default.
		if size := option.Config.JavaRingSize; size > 0 {
			agentServer.SetRingSize(uint64(size))
		}

		// The server runs for the rest of the Tetragon life.
		go func() {
			if err := agentServer.Listen(context.Background()); err != nil {
				logger.GetLogger().Error("Java agent control socket stopped", "error", err)
			}
		}()
	})

	return agentServer
}

// optionSocketPath returns path of the agent control socket, which the
// server listens on and the agents connect to (--java-agent-socket-path).
func optionSocketPath() string {
	// Read the configured value when the server is first needed, after option
	// parsing has completed.
	if option.Config.JavaAgentSocketPath != "" {
		return option.Config.JavaAgentSocketPath
	}

	return "/var/run/tetragon/java.sock"
}

// resolveNativeAgentPath returns path of the agent library to load into the
// JVMs, configuredPath is the --java-agent-path option value.
func resolveNativeAgentPath(configuredPath string) (string, error) {
	workingDir, _ := os.Getwd()
	return resolveNativeAgentPathFrom(configuredPath, workingDir, installedNativeAgentPath)
}

// resolveNativeAgentPathFrom looks for the agent library in following
// places and returns the first one that exists:
//
//   - configuredPath if it is set, relative path is taken from workingDir.
//     There is no fallback, missing configured library is an error.
//   - the library built in the source tree under workingDir, so Tetragon
//     started from the source tree uses its own build
//   - installedPath
func resolveNativeAgentPathFrom(configuredPath, workingDir, installedPath string) (string, error) {
	if configuredPath != "" {
		path := configuredPath
		if !filepath.IsAbs(path) {
			path = filepath.Join(workingDir, path)
		}
		path = filepath.Clean(path)

		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("configured JVMTI agent %q unavailable: %w", path, err)
		}

		return path, nil
	}

	if workingDir != "" {
		sourcePath := filepath.Join(workingDir, sourceNativeAgentPath)
		if _, err := os.Stat(sourcePath); err == nil {
			return sourcePath, nil
		}
	}

	if _, err := os.Stat(installedPath); err == nil {
		return installedPath, nil
	}

	return "", fmt.Errorf("JVMTI agent unavailable: checked source path %q and installed path %q", filepath.Join(workingDir, sourceNativeAgentPath), installedPath)
}

// PolicyHandler creates the java sensor for the policy, it returns nil for
// policy without the java section.
//
// It validates the policy targets and translates the policy hooks into
// the agent hooks. Nothing is started in here, that is done when the sensor
// is loaded.
func (policyHandler) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	filterID policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	spec := policy.TpSpec().Java
	if spec == nil {
		return nil, nil
	}

	if filterID != policyfilter.NoFilterID {
		return nil, errors.New("java policies do not support policy filtering")
	}

	// The executables are compared with the /proc/<pid>/exe link, so they
	// need to be in the same form.
	executables := make(map[string]struct{})
	if spec.Targets != nil {
		for _, path := range spec.Targets.Executables {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
				return nil, fmt.Errorf("java executable path %q must be absolute and clean", path)
			}
			executables[path] = struct{}{}
		}

		// Empty token would match any process, and the arguments in
		// /proc/<pid>/cmdline are separated by NUL, so token with NUL
		// would never match.
		for _, token := range spec.Targets.ProcessArgsContains {
			if token == "" || strings.ContainsRune(token, '\x00') {
				return nil, errors.New("java processArgsContains entries must be non-empty and contain no NUL")
			}
		}
	}

	if len(spec.Hooks) == 0 && len(executables) == 0 {
		return nil, errors.New("java policy without method hooks needs at least one executable target")
	}

	// The agent is needed only for policy with hooks. Make sure we have
	// the library now, so the policy fails to load without it.
	agentEnabled := len(spec.Hooks) != 0
	agentPath := ""
	if agentEnabled {
		var err error
		agentPath, err = resolveNativeAgentPath(option.Config.JavaAgentPath)
		if err != nil {
			return nil, err
		}
	}

	agentPolicy := javaagent.Policy{
		ID:   uint32(filterID),
		Name: tracingpolicy.TpLongname(policy),
		Meta: make(map[uint32]javaagent.HookMetadata),
	}

	// Policy IDs used by the JVMTI agent must be unique even when policy
	// filtering is disabled (NoFilterID is zero). Sensor manager allocates a
	// stable per-policy ID separately from the filter ID; use a local hash for
	// the agent namespace until that ID is exposed to policy handlers.
	agentPolicy.ID = policyID(policy)

	// Translate each policy hook into the agent hook, the hook id is its
	// index in the policy. The agent sends the id back with the method
	// definition, so we can find the hook metadata for the event.
	for i, hook := range spec.Hooks {
		if (hook.Class == "") == (hook.ClassPrefix == "") {
			return nil, fmt.Errorf("java.hooks[%d] requires exactly one of class or classPrefix", i)
		}

		class := hook.Class
		kind := uint8(javaagent.HookClass)
		if class == "" {
			class = hook.ClassPrefix
			kind = javaagent.HookPrefix
		}

		// The agent matches class names in the JVM internal form, which
		// has slashes instead of dots (java/lang/String).
		class = strings.ReplaceAll(class, ".", "/")

		// Hook without methods stands for all methods of the class.
		methods := make([]javaagent.HookMethod, 0, len(hook.Methods))
		for _, m := range hook.Methods {
			methods = append(methods, javaagent.HookMethod{Name: m.Name, Descriptor: m.Descriptor})
		}

		agentPolicy.Hooks = append(agentPolicy.Hooks, javaagent.Hook{
			PolicyID: agentPolicy.ID,
			HookID:   uint32(i),
			Kind:     kind,
			Class:    class,
			Methods:  methods,
		})

		// The message and tags are not sent to the agent, the control
		// server adds them to the events of the hook.
		agentPolicy.Meta[uint32(i)] = javaagent.HookMetadata{
			Message: hook.Message,
			Tags:    append([]string(nil), hook.Tags...),
		}
	}

	args := []string(nil)
	if spec.Targets != nil {
		args = append(args, spec.Targets.ProcessArgsContains...)
	}

	return &javaSensor{
		Sensor: &sensors.Sensor{
			Name:      sensorName + ":" + policy.TpName(),
			Policy:    policy.TpName(),
			Namespace: policy.TpNamespace(),
		},
		policy:       agentPolicy,
		agentPath:    agentPath,
		agentEnabled: agentEnabled,
		executables:  executables,
		argsContain:  args,
		active:       make(map[int]processIdentity),
		lastAttempt:  make(map[int]time.Time),
		waiting:      make(map[processIdentity]time.Time),
	}, nil
}

// policyID returns the id that identifies the policy for the agent, it is
// a hash of the policy name (with namespace). The agent that connects back
// after Tetragon restart then gets the same id for the same policy.
func policyID(policy tracingpolicy.TracingPolicy) uint32 {
	// FNV-1a keeps the protocol's u32 policy key stable across daemon restarts.
	h := uint32(2166136261)
	for _, b := range []byte(tracingpolicy.TpLongname(policy)) {
		h ^= uint32(b)
		h *= 16777619
	}

	if h == 0 {
		return 1
	}

	return h
}

// Load starts the sensor: it passes the policy to the agent control server,
// attaches to the JVMs that match the policy now and starts the watch
// goroutine to pick up the ones that show up later.
func (s *javaSensor) Load(_ string) error {
	s.mu.Lock()
	if s.Loaded {
		s.mu.Unlock()
		return fmt.Errorf("java sensor %q is already loaded", s.Name)
	}
	if s.Destroyed {
		s.mu.Unlock()
		return fmt.Errorf("java sensor %q was destroyed", s.Name)
	}

	// The sensor can be loaded again after unload, start with fresh
	// state.
	if s.agentEnabled {
		s.stop = make(chan struct{})
		s.done = make(chan struct{})
		s.lastAttempt = make(map[int]time.Time)
		s.waiting = make(map[processIdentity]time.Time)
	}
	s.Loaded = true
	s.mu.Unlock()

	if !s.agentEnabled {
		return nil
	}

	// The server needs the policy before the first agent connects, the
	// policy also reaches agents that are connected already.
	server := ensureServer()
	if err := server.SetPolicy(s.policy); err != nil {
		_ = s.Unload(true)
		return err
	}

	// Failed scan is not fatal, the watch goroutine tries again.
	if err := s.scan(); err != nil {
		logger.GetLogger().Warn("Java JVM scan failed", "policy", s.Policy, "error", err)
	}

	go s.watch()
	return nil
}

// watch runs the scan every scanInterval until the sensor is unloaded.
func (s *javaSensor) watch() {
	defer close(s.done)

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if err := s.scan(); err != nil {
				logger.GetLogger().Warn("Java JVM scan failed", "policy", s.Policy, "error", err)
			}
		}
	}
}

// scan finds the JVMs that match the policy targets and makes sure each of
// them has the agent and is authorized for the policy. It also forgets the
// JVMs that are gone.
//
// Returns the first attach error, the failed JVMs are tried again in
// following scans.
func (s *javaSensor) scan() error {
	candidates, err := matchingProcesses(s.executables, s.argsContain)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The sensor was unloaded while we were reading /proc.
	if !s.Loaded {
		return nil
	}

	server := ensureServer()

	// present has all the matching JVMs, pid -> start time.
	present := make(map[int]uint64, len(candidates))
	var first error

	for _, target := range candidates {
		present[target.pid] = target.startTicks

		if current, ok := s.active[target.pid]; ok && current.startTicks == target.startTicks {
			// We have this JVM already.
			continue
		} else if ok {
			// The pid was reused by another JVM, forget the old one
			// and go on with the new one.
			delete(s.active, target.pid)
			server.RevokeProcess(s.policy.ID, uint32(target.pid))

			attachedMu.Lock()
			if refs := attachedVMs[current]; refs <= 1 {
				delete(attachedVMs, current)
			} else {
				attachedVMs[current] = refs - 1
			}
			attachedMu.Unlock()
		}

		// The server accepts the agent connection only from authorized
		// JVM, so this needs to be done before the attach. If the agent
		// is connected already, the policy is sent to it right away.
		if err := server.AllowProcess(s.policy.ID, uint32(target.pid), target.startTicks); err != nil {
			logger.GetLogger().Warn("Java policy was not applied to JVM",
				"policy", s.Policy, "pid", target.pid, "error", err)
		}

		// The agent loaded by previous Tetragon instance connects on
		// its own.
		if s.waitForAgent(server, target) {
			continue
		}

		// The last attach failed, do not try again too early.
		if last, ok := s.lastAttempt[target.pid]; ok && time.Since(last) < retryInterval {
			continue
		}
		s.lastAttempt[target.pid] = time.Now()

		attachedMu.Lock()

		// Another policy attached to the JVM already, share its agent.
		refs := attachedVMs[target]
		if refs > 0 {
			attachedVMs[target] = refs + 1
			attachedMu.Unlock()
			s.setActive(target)
			continue
		}

		// Load the agent into the JVM. There is no use for the
		// authorization without the agent, take it back on failure.
		if err := s.attach(target); err != nil {
			attachedMu.Unlock()
			server.RevokeProcess(s.policy.ID, uint32(target.pid))
			if first == nil {
				first = fmt.Errorf("attach JVMTI agent to pid %d: %w", target.pid, err)
			}
			continue
		}

		attachedVMs[target] = 1
		attachedMu.Unlock()

		s.setActive(target)
		logger.GetLogger().Info("Java agent attached", "policy", s.Policy, "pid", target.pid)
	}

	// Stop waiting for agents of JVMs that are gone.
	for target := range s.waiting {
		if start, ok := present[target.pid]; !ok || start != target.startTicks {
			delete(s.waiting, target)
		}
	}

	// Forget the active JVMs that are gone.
	for pid, target := range s.active {
		if start, ok := present[pid]; ok && start == target.startTicks {
			continue
		}

		// The JVM is not among the matching processes, but it could
		// have been just missed by the /proc scan. Drop it only if the
		// process exited or its pid belongs to another process now.
		current, err := readProcessIdentity(pid)
		if err != nil || current.startTicks != target.startTicks {
			delete(s.active, pid)
			server.RevokeProcess(s.policy.ID, uint32(pid))

			attachedMu.Lock()
			if refs := attachedVMs[target]; refs <= 1 {
				delete(attachedVMs, target)
			} else {
				attachedVMs[target] = refs - 1
			}
			attachedMu.Unlock()
		}
	}

	return first
}

// setActive records that the JVM has the agent and the policy applies to it.
// Called with s.mu held.
func (s *javaSensor) setActive(target processIdentity) {
	s.active[target.pid] = target
	delete(s.lastAttempt, target.pid)
	delete(s.waiting, target)
}

// waitForAgent handles JVM that already has the agent, loaded by previous
// Tetragon instance. Such agent connects back on its own, so there is no need
// to attach to the JVM again. It returns true when the JVM needs no attach
// in this scan: the agent is either connected or still expected to connect.
// Called with s.mu held.
func (s *javaSensor) waitForAgent(server *javaagent.Server, target processIdentity) bool {
	attachedMu.Lock()
	refs := attachedVMs[target]
	attachedMu.Unlock()

	if refs > 0 {
		// attached by this Tetragon instance for another policy
		return false
	}

	// The agent is connected, take the JVM as attached.
	if server.Connected(uint32(target.pid), target.startTicks) {
		attachedMu.Lock()
		attachedVMs[target]++
		attachedMu.Unlock()

		s.setActive(target)
		logger.GetLogger().Info("Java agent already connected", "policy", s.Policy, "pid", target.pid)
		return true
	}

	// The agent is not connected. Start to wait for it if the JVM has
	// the agent library mapped, otherwise the JVM needs the attach.
	since, ok := s.waiting[target]
	if !ok {
		if !agentMapped(target.pid) {
			return false
		}
		since = time.Now()
		s.waiting[target] = since
	}

	if time.Since(since) < reconnectGrace {
		return true
	}

	// The agent did not connect back, attach to wake it up and to give
	// it the current socket path.
	delete(s.waiting, target)
	return false
}

// agentMapped reports whether the process has the JVMTI agent loaded.
func agentMapped(pid int) bool {
	maps, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	return err == nil && hasAgentMapping(maps)
}

// hasAgentMapping looks for the copy of the agent library, that attach puts
// under /tmp of the JVM, in the content of the process maps file.
func hasAgentMapping(maps []byte) bool {
	return bytes.Contains(maps, []byte("/"+agentFilePrefix))
}

// attach loads the agent into the JVM.
//
// The JVM loads the library from its own mount namespace, where our agent
// library is not visible for JVM in a container. So the library is copied
// into the JVM's /tmp first, and the JVM gets the path of the copy.
//
// Called with s.mu and attachedMu held.
func (s *javaSensor) attach(target processIdentity) error {
	// Make sure the pid still belongs to the JVM we found in the scan.
	current, err := readProcessIdentity(target.pid)
	if err != nil {
		return err
	}
	if current.startTicks != target.startTicks {
		return errors.New("process exited or PID was reused")
	}

	data, err := os.ReadFile(s.agentPath)
	if err != nil {
		return err
	}

	// The JVM's /tmp as we see it, the file name carries the process
	// identity, so the copy is not shared between JVMs.
	procRoot := filepath.Join("/proc", strconv.Itoa(target.pid), "root", "tmp")
	path := filepath.Join(
		procRoot,
		fmt.Sprintf(agentFilePrefix+"%d-%d.so", target.pid, target.startTicks),
	)

	if err := writeAgentFile(path, data); err != nil {
		return err
	}

	// The file is not needed once the JVM has the library mapped. The
	// mapping stays in /proc/<pid>/maps (as deleted), which is what
	// agentMapped looks for.
	defer os.Remove(path)

	// The library path is the one the JVM sees, the agent gets the control
	// socket path in its options.
	return javaattach.LoadNativeAgent(
		target.pid,
		filepath.Join("/tmp", filepath.Base(path)),
		optionSocketPath(),
	)
}

// writeAgentFile creates the copy of the agent library in path, readable
// and executable for all users, so the JVM can load it whatever user it
// runs as.
func writeAgentFile(path string, data []byte) error {
	// O_EXCL makes sure we create the file and do not write through
	// a symlink that somebody could leave in the JVM's /tmp.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)

	// The copy left by earlier attach attempt is used as it is.
	if errors.Is(err, os.ErrExist) {
		return os.Chmod(path, 0555)
	}
	if err != nil {
		return err
	}

	// Do not leave partial copy behind.
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		os.Remove(path)
		return werr
	}
	if cerr != nil {
		os.Remove(path)
		return cerr
	}

	return nil
}

// Unload stops the sensor: it stops the watch goroutine and removes the
// policy from the agent control server, which removes its hooks from the
// connected agents.
func (s *javaSensor) Unload(_ bool) error {
	s.mu.Lock()
	if !s.Loaded {
		s.mu.Unlock()
		return fmt.Errorf("java sensor %q is not loaded", s.Name)
	}
	s.Loaded = false

	if !s.agentEnabled {
		s.mu.Unlock()
		return nil
	}

	// Stop the watch goroutine and wait for it. The mutex is released
	// for the wait, because the scan in progress takes it.
	close(s.stop)
	done := s.done
	s.mu.Unlock()
	<-done

	// The agents stay in the JVMs. Forget them, so the policy is applied
	// to them again when the sensor is loaded next time.
	s.mu.Lock()
	attachedMu.Lock()
	for _, target := range s.active {
		if refs := attachedVMs[target]; refs <= 1 {
			delete(attachedVMs, target)
		} else {
			attachedVMs[target] = refs - 1
		}
	}
	attachedMu.Unlock()
	s.active = make(map[int]processIdentity)
	s.mu.Unlock()

	// Removes also the authorizations of all JVMs for the policy.
	return ensureServer().RemovePolicy(s.policy.ID)
}

// Destroy unloads the sensor if needed and marks it as destroyed, so it can
// not be loaded again.
func (s *javaSensor) Destroy(unpin bool) error {
	if s.Loaded {
		if err := s.Unload(unpin); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.Destroyed = true
	s.mu.Unlock()
	return nil
}

// matchingProcesses scans /proc and returns the JVMs that match the policy
// targets:
//
//   - executables, the /proc/<pid>/exe link must be one of them. Without
//     executables any process that has libjvm.so mapped is taken as JVM.
//   - argsContain, see containsArgs
//
// Process that we fail to read, most likely because it exited meanwhile, is
// skipped.
func matchingProcesses(
	executables map[string]struct{},
	argsContain []string,
) ([]processIdentity, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	matches := make([]processIdentity, 0)
	for _, entry := range entries {
		// Take only the process directories, and never the init.
		pid64, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil || pid64 <= 1 {
			continue
		}
		pid := int(pid64)
		proc := filepath.Join("/proc", entry.Name())

		// Kernel threads have no executable.
		exe, err := os.Readlink(filepath.Join(proc, "exe"))
		if err != nil {
			continue
		}

		if len(executables) > 0 {
			if _, ok := executables[exe]; !ok {
				continue
			}
		} else {
			maps, e := os.ReadFile(filepath.Join(proc, "maps"))
			if e != nil || !bytes.Contains(maps, []byte("libjvm.so")) {
				continue
			}
		}

		cmd, err := os.ReadFile(filepath.Join(proc, "cmdline"))
		if err != nil || !containsArgs(cmd, argsContain) {
			continue
		}

		ident, err := readProcessIdentity(pid)
		if err == nil {
			matches = append(matches, ident)
		}
	}

	return matches, nil
}

// containsArgs reports whether each of the required tokens is part of some
// process argument, cmd is the content of /proc/<pid>/cmdline, which has
// the arguments separated by NUL. It is true when there are no tokens.
func containsArgs(cmd []byte, required []string) bool {
	for _, token := range required {
		found := false
		for arg := range bytes.SplitSeq(cmd, []byte{0}) {
			if bytes.Contains(arg, []byte(token)) {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

// readProcessIdentity returns the identity of the process that has the pid
// now, it fails when there is no such process.
func readProcessIdentity(pid int) (processIdentity, error) {
	stats, err := proc.GetProcStatStrings(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return processIdentity{}, err
	}

	ticks, err := proc.GetStatsStartTicks(stats)
	if err != nil {
		return processIdentity{}, err
	}

	return processIdentity{pid: pid, startTicks: ticks}, nil
}
