// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaattach

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const attachTimeout = 10 * time.Second

// LoadNativeAgent asks a HotSpot VM to load a native JVMTI agent through its
// Unix-domain Attach listener. The library and its options must be visible in
// the target process's mount namespace.
func LoadNativeAgent(pid int, libraryPath, options string) error {
	if pid <= 1 {
		return fmt.Errorf("invalid JVM pid %d", pid)
	}
	if !filepath.IsAbs(libraryPath) || strings.ContainsRune(libraryPath, '\x00') {
		return errors.New("agent path must be absolute and contain no NUL")
	}
	if strings.ContainsRune(options, '\x00') {
		return errors.New("agent options contain NUL")
	}
	if len(libraryPath) > 1024 || len(options) > 1024 {
		return errors.New("Attach argument exceeds HotSpot's 1024-byte limit")
	}

	attachPID, err := namespacePID(pid)
	if err != nil {
		return fmt.Errorf("resolve target PID namespace: %w", err)
	}
	socket := filepath.Join("/proc", strconv.Itoa(pid), "root", "tmp", ".java_pid"+strconv.Itoa(attachPID))
	conn, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
	if err != nil {
		trigger, triggerErr := requestListener(pid, attachPID)
		if triggerErr != nil {
			return fmt.Errorf("start HotSpot Attach listener: %w", triggerErr)
		}
		defer os.Remove(trigger)

		deadline := time.Now().Add(attachTimeout)
		for time.Now().Before(deadline) {
			conn, err = net.DialTimeout("unix", socket, 250*time.Millisecond)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			return fmt.Errorf("connect to HotSpot Attach socket %s: %w", socket, err)
		}
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(attachTimeout)); err != nil {
		return fmt.Errorf("set Attach deadline: %w", err)
	}
	return loadRequest(conn, libraryPath, options)
}

func loadRequest(conn net.Conn, libraryPath, options string) error {
	// HotSpot's Linux Attach protocol uses NUL-terminated command fields.
	for _, field := range []string{"1", "load", libraryPath, "true", options} {
		if _, err := io.WriteString(conn, field+"\x00"); err != nil {
			return fmt.Errorf("write Attach request: %w", err)
		}
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("HotSpot Attach connection is not a Unix socket")
	}
	if err := unixConn.CloseWrite(); err != nil {
		return fmt.Errorf("finish Attach request: %w", err)
	}

	response := bufio.NewReader(conn)
	line, err := response.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read Attach status: %w", err)
	}
	status, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		return fmt.Errorf("invalid Attach status %q: %w", line, err)
	}
	message, _ := io.ReadAll(io.LimitReader(response, 4097))
	if status != 0 {
		return fmt.Errorf("HotSpot rejected JVMTI agent (status %d): %s", status, strings.TrimSpace(string(message)))
	}
	if strings.Contains(strings.ToLower(string(message)), "return code: -1") {
		return fmt.Errorf("JVMTI agent reported failure: %s", strings.TrimSpace(string(message)))
	}
	return nil
}

func namespacePID(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
		if len(fields) == 0 {
			return 0, errors.New("empty NSpid field")
		}
		value, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil || value <= 0 {
			return 0, fmt.Errorf("invalid NSpid field %q", line)
		}
		return value, nil
	}
	// A non-namespaced process may not expose NSpid on older kernels.
	return pid, nil
}

func requestListener(pid, attachPID int) (string, error) {
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	info, err := os.Stat(proc)
	if err != nil {
		return "", fmt.Errorf("stat target process: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot determine target process owner")
	}
	trigger := filepath.Join(proc, "root", "tmp", ".attach_pid"+strconv.Itoa(attachPID))
	file, err := os.OpenFile(trigger, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create Attach trigger: %w", err)
		}
	} else {
		if err = file.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			file.Close()
			os.Remove(trigger)
			return "", fmt.Errorf("set Attach trigger owner: %w", err)
		}
		if err = file.Close(); err != nil {
			os.Remove(trigger)
			return "", fmt.Errorf("close Attach trigger: %w", err)
		}
	}
	if err := syscall.Kill(pid, syscall.SIGQUIT); err != nil {
		os.Remove(trigger)
		return "", fmt.Errorf("signal target JVM: %w", err)
	}
	return trigger, nil
}
