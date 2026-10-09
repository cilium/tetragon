// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package java

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/javaattach"
	api "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	sensorName      = "java"
	nativeAgentPath = "/usr/lib/tetragon/tetragon-jvmti.so"
	manifestMagic   = "TGPAT01\n"
	maxManifestSize = 64 << 20
	maxClassSize    = 16 << 20
	maxPatchCount   = 32
	scanInterval    = time.Second
	retryInterval   = 5 * time.Second
)

type policyHandler struct{}

type processIdentity struct {
	pid        int
	startTicks uint64
}

type javaSensor struct {
	*sensors.Sensor
	mu          sync.Mutex
	executables map[string]struct{}
	argsContain []string
	patches     []api.JavaClassPatch
	nativeAgent []byte
	applyData   []byte
	revertData  []byte
	active      map[int]processIdentity
	lastAttempt map[int]time.Time
	stop        chan struct{}
	done        chan struct{}
	ready       chan struct{}
}

func init() {
	sensors.RegisterPolicyHandlerAtInit(sensorName, policyHandler{})
}

func (policyHandler) PolicyHandler(policy tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) (sensors.SensorIface, error) {
	if filterID != policyfilter.NoFilterID {
		return nil, errors.New("Java runtime policies do not support policy filtering")
	}
	spec := policy.TpSpec().Java
	if spec == nil {
		return nil, nil
	}
	if err := validate(spec); err != nil {
		return nil, err
	}
	nativeAgent, err := os.ReadFile(nativeAgentPath)
	if err != nil {
		return nil, fmt.Errorf("read packaged JVMTI helper %q: %w", nativeAgentPath, err)
	}
	if len(nativeAgent) == 0 {
		return nil, errors.New("packaged JVMTI helper is empty")
	}

	applyData, err := encodeManifest(spec.Patches, false)
	if err != nil {
		return nil, err
	}
	revertData, err := encodeManifest(spec.Patches, true)
	if err != nil {
		return nil, err
	}
	executables := make(map[string]struct{}, len(spec.Executables))
	for _, path := range spec.Executables {
		executables[filepath.Clean(path)] = struct{}{}
	}
	return &javaSensor{
		Sensor:      &sensors.Sensor{Name: sensorName + ":" + policy.TpName(), Policy: policy.TpName(), Namespace: policy.TpNamespace()},
		executables: executables,
		argsContain: append([]string(nil), spec.ProcessArgsContains...),
		patches:     append([]api.JavaClassPatch(nil), spec.Patches...),
		nativeAgent: nativeAgent,
		applyData:   applyData,
		revertData:  revertData,
		active:      make(map[int]processIdentity),
		lastAttempt: make(map[int]time.Time),
	}, nil
}

func validate(spec *api.JavaPolicySpec) error {
	if len(spec.Executables) == 0 {
		return errors.New("java.executables must contain at least one absolute executable path")
	}
	for _, path := range spec.Executables {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
			return fmt.Errorf("Java executable path %q must be absolute and cleaned", path)
		}
	}
	for _, token := range spec.ProcessArgsContains {
		if token == "" || strings.ContainsRune(token, '\x00') {
			return errors.New("java.processArgsContains entries must be non-empty and contain no NUL")
		}
	}
	if len(spec.Patches) == 0 || len(spec.Patches) > maxPatchCount {
		return fmt.Errorf("java.patches must contain 1 to %d class patches", maxPatchCount)
	}
	seen := make(map[string]struct{}, len(spec.Patches))
	total := 12
	for i, patch := range spec.Patches {
		if !validSignature(patch.Signature) {
			return fmt.Errorf("java.patches[%d].signature is not a JVM object signature", i)
		}
		if _, ok := seen[patch.Signature]; ok {
			return fmt.Errorf("duplicate Java class signature %q", patch.Signature)
		}
		seen[patch.Signature] = struct{}{}
		if len(patch.Signature) > 1024 || len(patch.Replacement) < 8 || len(patch.Replacement) > maxClassSize || len(patch.Rollback) < 8 || len(patch.Rollback) > maxClassSize {
			return fmt.Errorf("java.patches[%d] has an invalid class signature or class-file size", i)
		}
		magic := []byte{0xca, 0xfe, 0xba, 0xbe}
		if !bytes.HasPrefix(patch.Replacement, magic) || !bytes.HasPrefix(patch.Rollback, magic) {
			return fmt.Errorf("java.patches[%d] replacement and rollback must be Java class files", i)
		}
		total += 6 + len(patch.Signature) + len(patch.Replacement)
		if total > maxManifestSize {
			return fmt.Errorf("Java patch manifest exceeds %d bytes", maxManifestSize)
		}
	}
	return nil
}

func validSignature(signature string) bool {
	if len(signature) < 3 || signature[0] != 'L' || signature[len(signature)-1] != ';' {
		return false
	}
	name := signature[1 : len(signature)-1]
	if strings.ContainsAny(name, ".;[\x00") || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return false
	}
	return true
}

func encodeManifest(patches []api.JavaClassPatch, rollback bool) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(manifestMagic)
	if err := binary.Write(&out, binary.BigEndian, uint32(len(patches))); err != nil {
		return nil, err
	}
	for _, patch := range patches {
		classBytes := patch.Replacement
		if rollback {
			classBytes = patch.Rollback
		}
		if len(patch.Signature) > 0xffff || len(classBytes) > maxClassSize {
			return nil, fmt.Errorf("Java class patch %q exceeds manifest limits", patch.Signature)
		}
		if err := binary.Write(&out, binary.BigEndian, uint16(len(patch.Signature))); err != nil {
			return nil, err
		}
		if err := binary.Write(&out, binary.BigEndian, uint32(len(classBytes))); err != nil {
			return nil, err
		}
		out.WriteString(patch.Signature)
		out.Write(classBytes)
	}
	if out.Len() > maxManifestSize {
		return nil, fmt.Errorf("Java patch manifest exceeds %d bytes", maxManifestSize)
	}
	return out.Bytes(), nil
}

func (s *javaSensor) Load(_ string) error {
	s.mu.Lock()
	if s.Loaded {
		s.mu.Unlock()
		return fmt.Errorf("Java sensor %q is already loaded", s.Name)
	}
	if s.Destroyed {
		s.mu.Unlock()
		return fmt.Errorf("Java sensor %q has been destroyed", s.Name)
	}
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.ready = make(chan struct{})
	s.lastAttempt = make(map[int]time.Time)
	s.Loaded = true
	s.mu.Unlock()

	go s.watch()
	if err := s.scan(); err != nil {
		return errors.Join(err, s.Unload(true))
	}
	close(s.ready)
	return nil
}

func (s *javaSensor) watch() {
	defer close(s.done)
	select {
	case <-s.stop:
		return
	case <-s.ready:
	}
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if err := s.scan(); err != nil {
				logger.GetLogger().Warn("Java runtime patch retry failed", "policy", s.Policy, "error", err)
			}
		}
	}
}

func (s *javaSensor) scan() error {
	candidates, err := matchingProcesses(s.executables, s.argsContain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Loaded {
		return nil
	}
	var firstErr error
	present := make(map[int]uint64, len(candidates))
	for _, candidate := range candidates {
		present[candidate.pid] = candidate.startTicks
		if active, ok := s.active[candidate.pid]; ok && active.startTicks == candidate.startTicks {
			continue
		}
		if last, ok := s.lastAttempt[candidate.pid]; ok && time.Since(last) < retryInterval {
			continue
		}
		s.lastAttempt[candidate.pid] = time.Now()
		if err := s.redefine(candidate, s.applyData); err != nil {
			logger.GetLogger().Warn("Failed to patch matching JVM", "policy", s.Policy, "pid", candidate.pid, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("patch JVM pid %d: %w", candidate.pid, err)
			}
			continue
		}
		s.active[candidate.pid] = candidate
		delete(s.lastAttempt, candidate.pid)
		logger.GetLogger().Info("Applied Java class patch", "policy", s.Policy, "pid", candidate.pid)
	}
	for pid, target := range s.active {
		if start, ok := present[pid]; ok && start == target.startTicks {
			continue
		}
		if current, err := readProcessIdentity(pid); err != nil || current.startTicks != target.startTicks {
			delete(s.active, pid)
		}
	}

	return firstErr
}

func (s *javaSensor) redefine(target processIdentity, manifest []byte) error {
	procPath := filepath.Join("/proc", strconv.Itoa(target.pid))
	current, err := readProcessIdentity(target.pid)
	if err != nil {
		return err
	}
	if current.startTicks != target.startTicks {
		return errors.New("process exited or PID was reused")
	}
	processInfo, err := os.Stat(procPath)
	if err != nil {
		return fmt.Errorf("stat process: %w", err)
	}
	owner, ok := processInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine target process owner")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate staging directory name: %w", err)
	}
	dirName := ".tetragon-java-" + hex.EncodeToString(nonce[:])
	targetDir := filepath.Join(procPath, "root", "tmp", dirName)
	if err := os.Mkdir(targetDir, 0711); err != nil {
		return fmt.Errorf("create target staging directory: %w", err)
	}
	defer os.RemoveAll(targetDir)
	if err := os.Chown(targetDir, 0, 0); err != nil {
		return fmt.Errorf("secure target staging directory: %w", err)
	}

	manifestHash := sha256.Sum256(manifest)
	manifestName := "patch-" + hex.EncodeToString(manifestHash[:8]) + ".bin"
	targetManifest := filepath.Join(targetDir, manifestName)
	if err := writeTargetFile(targetManifest, manifest, int(owner.Uid), int(owner.Gid), 0400); err != nil {
		return fmt.Errorf("stage class patch manifest: %w", err)
	}
	libraryName := "agent-" + hex.EncodeToString(nonce[:]) + ".so"
	targetLibrary := filepath.Join(targetDir, libraryName)
	if err := writeTargetFile(targetLibrary, s.nativeAgent, int(owner.Uid), int(owner.Gid), 0500); err != nil {
		return fmt.Errorf("stage JVMTI helper: %w", err)
	}
	attachLibrary := filepath.Join("/tmp", dirName, libraryName)
	attachManifest := filepath.Join("/tmp", dirName, manifestName)
	return javaattach.LoadNativeAgent(target.pid, attachLibrary, attachManifest)
}

func writeTargetFile(path string, data []byte, uid, gid, mode int) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(mode))
	if err != nil {
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	return file.Close()
}

func (s *javaSensor) Unload(_ bool) error {
	s.mu.Lock()
	if !s.Loaded {
		s.mu.Unlock()
		return fmt.Errorf("Java sensor %q is not loaded", s.Name)
	}
	stop, done := s.stop, s.done
	s.Loaded = false
	close(stop)
	s.mu.Unlock()
	<-done

	s.mu.Lock()
	defer s.mu.Unlock()
	var errs error
	for pid, target := range s.active {
		current, err := readProcessIdentity(pid)
		if err != nil || current.startTicks != target.startTicks {
			delete(s.active, pid)
			continue
		}
		if err := s.redefine(target, s.revertData); err != nil {
			errs = errors.Join(errs, fmt.Errorf("rollback Java patch in pid %d: %w", pid, err))
			continue
		}
		logger.GetLogger().Info("Reverted Java class patch", "policy", s.Policy, "pid", pid)
		delete(s.active, pid)
	}
	return errs
}

func (s *javaSensor) Destroy(unpin bool) error {
	if s.Loaded {
		if err := s.Unload(unpin); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if len(s.active) != 0 {
		var errs error
		for pid, target := range s.active {
			if err := s.redefine(target, s.revertData); err != nil {
				errs = errors.Join(errs, fmt.Errorf("rollback Java patch in pid %d: %w", pid, err))
				continue
			}
			delete(s.active, pid)
		}
		if errs != nil {
			s.mu.Unlock()
			return errs
		}
	}
	s.mu.Unlock()
	s.mu.Lock()
	s.Destroyed = true
	s.mu.Unlock()
	return nil
}

func matchingProcesses(executables map[string]struct{}, argsContain []string) ([]processIdentity, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read procfs: %w", err)
	}
	var matches []processIdentity
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		procPath := filepath.Join("/proc", entry.Name())
		executable, err := os.Readlink(filepath.Join(procPath, "exe"))
		if err != nil {
			continue
		}
		if _, ok := executables[executable]; !ok {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
		if err != nil || !containsArgs(cmdline, argsContain) {
			continue
		}
		identity, err := readProcessIdentity(pid)
		if err != nil {
			continue
		}
		matches = append(matches, identity)
	}
	return matches, nil
}

func containsArgs(cmdline []byte, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, token := range required {
		found := false
		for _, arg := range bytes.Split(cmdline, []byte{0}) {
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

func readProcessIdentity(pid int) (processIdentity, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return processIdentity{}, err
	}
	// comm is parenthesized and may itself contain spaces or ')'.
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+1 >= len(data) {
		return processIdentity{}, errors.New("malformed proc stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	// The first field is state (field 3); starttime is field 22.
	if len(fields) <= 19 {
		return processIdentity{}, errors.New("proc stat lacks start time")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processIdentity{}, fmt.Errorf("parse process start time: %w", err)
	}
	return processIdentity{pid: pid, startTicks: startTicks}, nil
}
