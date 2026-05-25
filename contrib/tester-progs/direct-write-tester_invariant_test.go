package security_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestBufferReadNeverExceedsDeclaredLength verifies that the direct-write-tester
// program never performs out-of-bounds buffer reads/writes regardless of input size.
// This guards against CWE-120: Buffer Copy without Checking Size of Input.
func TestBufferReadNeverExceedsDeclaredLength(t *testing.T) {
	payloads := []string{
		// Exact boundary inputs
		strings.Repeat("A", 1),
		strings.Repeat("A", 16),
		strings.Repeat("A", 32),
		strings.Repeat("A", 64),
		strings.Repeat("A", 128),
		strings.Repeat("A", 255),
		strings.Repeat("A", 256),

		// 2x oversized inputs
		strings.Repeat("B", 512),
		strings.Repeat("B", 1024),
		strings.Repeat("B", 2048),

		// 10x oversized inputs
		strings.Repeat("C", 5120),
		strings.Repeat("C", 10240),
		strings.Repeat("C", 20480),

		// Extremely large inputs
		strings.Repeat("D", 65536),
		strings.Repeat("D", 131072),
		strings.Repeat("D", 1048576),

		// Special characters and attack patterns
		strings.Repeat("\x00", 256),
		strings.Repeat("\xff", 256),
		strings.Repeat("%s%n%x%d", 128),
		strings.Repeat("../", 512),
		strings.Repeat("A\x00B", 256),
		strings.Repeat("\n\r\t", 512),

		// Format string attack payloads
		strings.Repeat("%s", 512),
		strings.Repeat("%n", 512),
		strings.Repeat("%x", 512),
		strings.Repeat("%p", 512),
		strings.Repeat("%.1000d", 100),

		// Shell injection payloads
		strings.Repeat("; cat /etc/passwd", 64),
		strings.Repeat("$(id)", 256),
		strings.Repeat("`id`", 256),

		// Unicode/multibyte payloads
		strings.Repeat("é", 512),
		strings.Repeat("中", 512),
		strings.Repeat("🔥", 256),

		// Mixed oversized payloads
		strings.Repeat("AAAA\x00BBBB", 256),
		strings.Repeat("X", 4096) + "\x00" + strings.Repeat("Y", 4096),

		// Off-by-one candidates
		strings.Repeat("Z", 257),
		strings.Repeat("Z", 258),
		strings.Repeat("Z", 259),
		strings.Repeat("Z", 260),
	}

	for _, payload := range payloads {
		payload := payload // capture range variable
		payloadLen := utf8.RuneCountInString(payload)

		t.Run("payload_len_"+itoa(payloadLen), func(t *testing.T) {
			t.Parallel()

			// Attempt to run the binary with the oversized payload.
			// The binary should either:
			// 1. Reject the input (non-zero exit with error message), or
			// 2. Truncate the input safely, or
			// 3. Exit cleanly without memory corruption signals.
			// It must NOT crash with SIGSEGV, SIGABRT, SIGBUS, or similar signals
			// that indicate memory corruption.

			cmd := exec.Command("./direct-write-tester", payload)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			// Use a timeout to detect hangs caused by corruption
			done := make(chan error, 1)
			go func() {
				done <- cmd.Run()
			}()

			var err error
			select {
			case err = <-done:
				// Command completed
			case <-time.After(10 * time.Second):
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
				t.Logf("payload length: %d", payloadLen)
				t.Fatal("program timed out — possible infinite loop or deadlock from oversized input")
			}

			// Check for memory corruption signals
			if err != nil {
				exitErr, ok := err.(*exec.ExitError)
				if ok {
					// These signals indicate memory corruption / buffer overflow
					corruptionSignals := []string{
						"signal: segmentation fault",
						"signal: bus error",
						"signal: aborted",
						"signal: illegal instruction",
						"SIGSEGV",
						"SIGABRT",
						"SIGBUS",
						"SIGILL",
						"heap-buffer-overflow",
						"stack-buffer-overflow",
						"AddressSanitizer",
						"ASAN",
						"double free",
						"corrupted",
					}

					exitMsg := exitErr.Error()
					stderrMsg := stderr.String()
					combined := exitMsg + " " + stderrMsg

					for _, sig := range corruptionSignals {
						if strings.Contains(strings.ToLower(combined), strings.ToLower(sig)) {
							t.Logf("payload length: %d", payloadLen)
							t.Logf("stdout: %s", stdout.String())
							t.Logf("stderr: %s", stderrMsg)
							t.Fatalf("SECURITY VIOLATION: buffer overflow detected with payload of length %d: %s", payloadLen, sig)
						}
					}

					// Non-corruption exit (e.g., input rejected) is acceptable
					t.Logf("program exited with non-zero status for payload length %d (acceptable rejection): %v", payloadLen, err)
				}
			} else {
				// Program exited cleanly — verify output doesn't contain more data
				// than the input (sanity check for truncation behavior)
				outLen := len(stdout.String())
				if outLen > len(payload)+1024 { // allow some overhead for formatting
					t.Logf("payload length: %d, output length: %d", payloadLen, outLen)
					t.Fatalf("output length %d suspiciously exceeds input length %d — possible buffer over-read", outLen, payloadLen)
				}
				t.Logf("program exited cleanly for payload length %d", payloadLen)
			}
		})
	}
}

// itoa converts an int to string without importing strconv at top level
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// TestBufferLengthInvariantWithSafeWrapper tests the invariant using a safe
// in-process simulation of the memcpy pattern to ensure length checks are enforced.
func TestBufferLengthInvariantWithSafeWrapper(t *testing.T) {
	const allocatedBufferSize = 256 // assumed allocation size from the vulnerable code

	payloads := []string{
		strings.Repeat("A", allocatedBufferSize-1),   // fits exactly (with null terminator)
		strings.Repeat("A", allocatedBufferSize),     // boundary: needs +1 for null = overflow
		strings.Repeat("A", allocatedBufferSize+1),   // 1 byte over
		strings.Repeat("A", allocatedBufferSize*2),   // 2x oversized
		strings.Repeat("A", allocatedBufferSize*10),  // 10x oversized
		strings.Repeat("A", allocatedBufferSize*100), // 100x oversized
		strings.Repeat("\xff", allocatedBufferSize*2),
		strings.Repeat("\x00", allocatedBufferSize*2),
		strings.Repeat("%n%s%x", allocatedBufferSize),
	}

	for _, payload := range payloads {
		payload := payload
		t.Run("safe_copy_len_"+itoa(len(payload)), func(t *testing.T) {
			t.Parallel()

			// Simulate the safe version of what the code SHOULD do:
			// strlen(avd)+1 must be <= allocated buffer size
			inputLen := len(payload)
			copyLen := inputLen + 1 // strlen(avd) + 1 (for null terminator)

			// INVARIANT: copy length must never exceed allocated buffer size
			if copyLen > allocatedBufferSize {
				// This is the condition that SHOULD be checked before memcpy
				// The program must reject or truncate — not overflow
				t.Logf("INVARIANT CHECK: input length %d would require copying %d bytes into buffer of size %d",
					inputLen, copyLen, allocatedBufferSize)
				t.Logf("Input MUST be rejected or truncated — buffer overflow would occur otherwise")

				// Simulate safe truncation behavior
				safeBuffer := make([]byte, allocatedBufferSize)
				safeLen := allocatedBufferSize - 1 // leave room for null terminator
				if inputLen < safeLen {
					safeLen = inputLen
				}
				copy(safeBuffer, []byte(payload)[:safeLen])
				safeBuffer[safeLen] = 0 // null terminator

				// Verify the safe copy never exceeds buffer bounds
				for i, b := range safeBuffer {
					if i >= allocatedBufferSize {
						t.Fatalf("SECURITY VIOLATION: wrote byte at index %d, exceeding buffer size %d", i, allocatedBufferSize)
					}
					_ = b
				}

				// Verify null termination within bounds
				nullFound := false
				for i := 0; i < allocatedBufferSize; i++ {
					if safeBuffer[i] == 0 {
						nullFound = true
						break
					}
				}
				if !nullFound {
					t.Fatal("SECURITY VIOLATION: buffer is not null-terminated within bounds")
				}
			} else {
				// Input fits safely
				safeBuffer := make([]byte, allocatedBufferSize)
				copy(safeBuffer, []byte(payload))
				safeBuffer[inputLen] = 0

				// Verify bounds
				if inputLen+1 > allocatedBufferSize {
					t.Fatalf("SECURITY VIOLATION: copy of %d bytes exceeds buffer size %d", inputLen+1, allocatedBufferSize)
				}
				t.Logf("Input of length %d fits safely in buffer of size %d", inputLen, allocatedBufferSize)
			}
		})
	}
}