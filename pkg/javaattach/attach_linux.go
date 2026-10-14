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

// HotSpot Attach interface, the way tools like jcmd talk to running JVM:
//
//   - the JVM listens on /tmp/.java_pid<pid> unix socket, both the path and
//     the pid are the ones the JVM sees (its mount and pid namespace)
//   - the socket is created by the attach listener thread, which is not
//     started with the JVM. It is started on demand, when the JVM gets
//     SIGQUIT and finds the /tmp/.attach_pid<pid> trigger file
//   - each connection carries one command and its reply, see loadRequest
//
// We are in the host namespaces, so we get to the JVM's /tmp through
// /proc/<pid>/root and use the pid from the JVM's pid namespace in the
// file names.

// attachTimeout limits both the wait for the attach listener to start and
// the whole command exchange with the JVM.
const attachTimeout = 10 * time.Second

// LoadNativeAgent asks a HotSpot VM to load a native JVMTI agent through its
// Unix-domain Attach listener. The library and its options must be visible in
// the target process's mount namespace.
//
// The pid is the JVM's pid in our (host) pid namespace. The JVM loads the
// library and calls its Agent_OnAttach function with the options, the error
// is returned when either the JVM refuses the command or the agent fails.
func LoadNativeAgent(pid int, libraryPath, options string) error {
	if pid <= 1 {
		return fmt.Errorf("invalid JVM pid %d", pid)
	}

	// The command fields are NUL-terminated strings, so NUL in any of them
	// would add another field to the command.
	if !filepath.IsAbs(libraryPath) || strings.ContainsRune(libraryPath, '\x00') {
		return errors.New("agent path must be absolute and contain no NUL")
	}
	if strings.ContainsRune(options, '\x00') {
		return errors.New("agent options contain NUL")
	}
	if len(libraryPath) > 1024 || len(options) > 1024 {
		return errors.New("attach argument exceeds HotSpot's 1024-byte limit")
	}

	// The JVM names its socket and the trigger file with the pid it sees.
	attachPID, err := namespacePID(pid)
	if err != nil {
		return fmt.Errorf("resolve target PID namespace: %w", err)
	}

	socket := filepath.Join(
		"/proc", strconv.Itoa(pid), "root", "tmp",
		".java_pid"+strconv.Itoa(attachPID),
	)

	// The socket is there if the attach listener runs already, which is
	// the case when something attached to the JVM before.
	conn, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
	if err != nil {
		// Start the attach listener and wait for its socket to show up.
		trigger, triggerErr := requestListener(pid, attachPID)
		if triggerErr != nil {
			return fmt.Errorf("start HotSpot Attach listener: %w", triggerErr)
		}

		// The trigger file is needed only until the listener starts.
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

	// The JVM runs Agent_OnAttach before it replies, do not wait for it
	// forever.
	if err := conn.SetDeadline(time.Now().Add(attachTimeout)); err != nil {
		return fmt.Errorf("set Attach deadline: %w", err)
	}

	return loadRequest(conn, libraryPath, options)
}

// loadRequest sends the load command on the connection to the attach
// listener and checks the reply.
//
// The command is a sequence of NUL-terminated strings:
//
//	"1"      protocol version
//	"load"   command name
//	path     the agent library
//	"true"   the path is absolute, the JVM does not search for the library
//	options  passed to Agent_OnAttach
//
// The reply is the command status on the first line (0 for success)
// followed by the command output, which carries the return code of
// Agent_OnAttach or the reason of the failure.
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

	// The command is complete, close our side for writing, the reply
	// still comes on the read side.
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

	// The output is used just for the error message, so there is no need
	// to read all of it. The JVM closes the connection behind the reply.
	message, _ := io.ReadAll(io.LimitReader(response, 4097))

	// The JVM failed the command, the library was not loaded or has no
	// Agent_OnAttach function.
	if status != 0 {
		return fmt.Errorf(
			"HotSpot rejected JVMTI agent (status %d): %s",
			status,
			strings.TrimSpace(string(message)),
		)
	}

	// The command succeeded for the JVM, but our Agent_OnAttach returned
	// error (JNI_ERR), which the JVM reports just in the output.
	if strings.Contains(strings.ToLower(string(message)), "return code: -1") {
		return fmt.Errorf("JVMTI agent reported failure: %s", strings.TrimSpace(string(message)))
	}

	return nil
}

// namespacePID returns the pid of the process in its own pid namespace,
// which differs from pid for process in a container.
//
// It is taken from the NSpid line of /proc/<pid>/status, that has the pid
// of the process in each pid namespace it is visible in, starting with
// ours and ending with the innermost one, which is the one the process
// sees:
//
//	NSpid:  251234  17
func namespacePID(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}

	for line := range strings.SplitSeq(string(data), "\n") {
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

// requestListener asks the JVM to start its attach listener: it creates the
// .attach_pid<attachPID> trigger file in the JVM's /tmp and sends SIGQUIT
// to the JVM. The JVM starts the listener from its signal handler thread,
// so the socket shows up later, the caller waits for it.
//
// Returns path of the trigger file, the caller removes it.
func requestListener(pid, attachPID int) (string, error) {
	proc := filepath.Join("/proc", strconv.Itoa(pid))

	// The /proc/<pid> directory is owned by the user the process runs as.
	info, err := os.Stat(proc)
	if err != nil {
		return "", fmt.Errorf("stat target process: %w", err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot determine target process owner")
	}

	trigger := filepath.Join(proc, "root", "tmp", ".attach_pid"+strconv.Itoa(attachPID))

	// O_EXCL makes sure we create the file and do not follow a symlink
	// that somebody could leave in the JVM's /tmp.
	file, err := os.OpenFile(trigger, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		// The file left by another attach in progress works for us too.
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create Attach trigger: %w", err)
		}
	} else {
		// The JVM takes the trigger file only from its own user, and we
		// created it as root.
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

	// With the trigger file in place the JVM starts the attach listener,
	// without it SIGQUIT makes the JVM print the thread dump.
	if err := syscall.Kill(pid, syscall.SIGQUIT); err != nil {
		os.Remove(trigger)
		return "", fmt.Errorf("signal target JVM: %w", err)
	}

	return trigger, nil
}
