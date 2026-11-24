// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaattach

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for the class file rewriter of the jvmti agent (agent/classfile.c).
//
// The rewriter is driven by agent/classfile-test.c, which rewrites compiled
// testdata/classfile sources without the agent. The rewritten classes then
// run on the JVM with testdata TetragonHook class, that records the keys
// it is called with.

const (
	classfileAgentDir = "agent"
	classfileDataDir  = "testdata/classfile"
)

// classfileCalls are the hooked methods each test case of Main.java goes
// through, in the order they are called.
var classfileCalls = map[string][]string{
	"staticAdd":     {"Cases.staticAdd"},
	"instanceMul":   {"Cases.<init>", "Cases.instanceMul"},
	"constructor":   {"Cases.constructor", "Cases$Box.<init>", "Cases$Box.get"},
	"defaultMethod": {"Cases.defaultMethod", "Cases$1.<init>", "Cases$Greeter.greet"},
	"denseSwitch":   {"Cases.denseSwitch", "Cases.denseSwitch", "Cases.denseSwitch"},
	"sparseSwitch":  {"Cases.sparseSwitch", "Cases.sparseSwitch", "Cases.sparseSwitch"},
	"tryCatch":      {"Cases.tryCatch", "Cases.tryCatch"},
	"loop":          {"Cases.loop"},
	"loopAtStart":   {"Cases.loopAtStart"},
	"uninitialized": {"Cases.uninitialized", "Cases.uninitialized"},
	"wide":          {"Cases.wide"},
	"lambda":        {"Cases.lambda", "Cases.lambda$lambda$0"},
	"stringSwitch":  {"Cases.stringSwitch", "Cases.stringSwitch", "Cases.stringSwitch"},
	"record":        {"Cases.record", "Cases$Point.<init>", "Cases$Point.x", "Cases$Point.y"},
	"patternSwitch": {
		"Cases.patternSwitch", "Cases.patternSwitch", "Cases.patternSwitch", "Cases.patternSwitch",
	},
	"generics": {"Cases.generics"},
	"abstractMethod": {
		"Cases.abstractMethod", "Cases$Impl.<init>", "Cases$Abs.<init>", "Cases$Abs.b", "Cases$Impl.a",
	},
	// the method is too big to get the call, its class stays unchanged
	"big": nil,
}

// classfileMinJDK is the oldest JDK the tests run with, Cases.java uses
// pattern matching for switch, which is not available before it.
const classfileMinJDK = 21

func classfileTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
}

// classfileMajor returns the JDK major version from the output of the JDK
// tool run with -version, like:
//
//	javac 21.0.2
//	javac 27-ea
//	javac 1.8.0_292
//	openjdk version "21.0.2" 2024-01-16
//
// The versions before 9 start with 1, their major version is the second
// number.
func classfileMajor(output string) (int, bool) {
	for line := range strings.SplitSeq(output, "\n") {
		// The JVM reports options it takes from the environment first.
		if strings.HasPrefix(line, "Picked up ") {
			continue
		}

		i := strings.IndexAny(line, "0123456789")
		if i < 0 {
			continue
		}

		nums := strings.FieldsFunc(line[i:], func(r rune) bool { return r < '0' || r > '9' })
		major, err := strconv.Atoi(nums[0])
		if err == nil && major == 1 && len(nums) > 1 {
			major, err = strconv.Atoi(nums[1])
		}
		return major, err == nil
	}

	return 0, false
}

// classfileJDK skips the test if any of the JDK tools is older than
// classfileMinJDK.
func classfileJDK(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		// javac prints the version to stdout, java to stderr.
		output, err := exec.Command(tool, "-version").CombinedOutput()
		if err != nil {
			t.Skipf("failed to get %s version: %v", tool, err)
		}

		major, ok := classfileMajor(string(output))
		if !ok {
			t.Skipf("failed to parse %s version %q", tool, strings.TrimSpace(string(output)))
		}
		if major < classfileMinJDK {
			t.Skipf("%s version %d is too old, need at least %d", tool, major, classfileMinJDK)
		}
	}
}

func TestClassfileMajor(t *testing.T) {
	for _, tc := range []struct {
		output string
		major  int
		ok     bool
	}{
		{"javac 21.0.2\n", 21, true},
		{"javac 27-ea\n", 27, true},
		{"javac 17.0.9\n", 17, true},
		{"javac 1.8.0_292\n", 8, true},
		{"openjdk version \"21.0.2\" 2024-01-16\nOpenJDK Runtime Environment\n", 21, true},
		{"java version \"1.8.0_292\"\n", 8, true},
		{"Picked up JAVA_TOOL_OPTIONS: -Xmx1g\njavac 21.0.2\n", 21, true},
		{"javac unknown\n", 0, false},
		{"", 0, false},
	} {
		major, ok := classfileMajor(tc.output)
		require.Equal(t, tc.ok, ok, "output %q", tc.output)
		require.Equal(t, tc.major, major, "output %q", tc.output)
	}
}

// classfileDriver builds the rewriter test driver. It is built with
// sanitizers if there is compiler that has them.
func classfileDriver(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "classfile-test")
	var log bytes.Buffer
	for _, args := range [][]string{
		nil,
		{"CC=clang"},
		{"TEST_CFLAGS=-O1 -g"},
	} {
		args = append([]string{"-C", classfileAgentDir, "test-driver", "TEST_OUT=" + out}, args...)
		output, err := exec.Command("make", args...).CombinedOutput()
		if err == nil {
			if strings.Contains(strings.Join(args, " "), "TEST_CFLAGS") {
				t.Log("classfile-test is built without sanitizers")
			}
			return out
		}
		log.Write(output)
	}
	require.FailNow(t, "failed to build classfile-test", log.String())
	return ""
}

// classfileCompile compiles the test classes together with generated Big
// class, which has a method with bytecode that is 8 bytes below the 64K
// limit, so there is no room for the call in it.
func classfileCompile(t *testing.T, dir string) string {
	t.Helper()
	var big strings.Builder
	big.WriteString("public class Big {\n    static int big(int x) {\n")
	// 6 bytes of wide iinc for each line, followed by iload_0 and ireturn
	big.WriteString(strings.Repeat("        x += 1000;\n", 10921))
	big.WriteString("        return x;\n    }\n}\n")
	bigPath := filepath.Join(dir, "Big.java")
	require.NoError(t, os.WriteFile(bigPath, []byte(big.String()), 0644))

	out := filepath.Join(dir, "orig")
	cmd := exec.Command("javac", "-g", "-d", out,
		filepath.Join(classfileDataDir, "Main.java"),
		filepath.Join(classfileDataDir, "Cases.java"),
		filepath.Join(classfileDataDir, "io/tetragon/TetragonHook.java"),
		bigPath)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	return out
}

type classfileResult struct {
	result string
	keys   []uint64
}

// classfileMain runs Main from the class path and returns its report for
// each test case.
func classfileMain(t *testing.T, classPath string) map[string]classfileResult {
	t.Helper()
	output, err := exec.Command("java", "-cp", classPath, "Main").CombinedOutput()
	require.NoError(t, err, string(output))

	results := make(map[string]classfileResult)
	for line := range strings.SplitSeq(strings.TrimRight(string(output), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		require.Len(t, fields, 3, "unexpected output line %q", line)
		res := classfileResult{result: fields[1]}
		if fields[2] != "" {
			for s := range strings.SplitSeq(fields[2], ",") {
				key, err := strconv.ParseUint(s, 10, 64)
				require.NoError(t, err)
				res.keys = append(res.keys, key)
			}
		}
		results[fields[0]] = res
	}
	return results
}

// classfileRewritten returns names of the test classes that get rewritten,
// which is everything but Main and the hook class.
func classfileRewritten(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	for _, pattern := range []string{"Cases*.class", "Big.class"} {
		paths, err := filepath.Glob(filepath.Join(dir, pattern))
		require.NoError(t, err)
		for _, path := range paths {
			names = append(names, filepath.Base(path))
		}
	}
	require.NotEmpty(t, names)
	return names
}

func TestClassfileRun(t *testing.T) {
	classfileTools(t, "make", "cc", "javac", "java", "javap")
	classfileJDK(t, "javac", "java")
	dir := t.TempDir()
	driver := classfileDriver(t, dir)
	orig := classfileCompile(t, dir)

	base := classfileMain(t, orig)
	require.Len(t, base, len(classfileCalls))
	for name, res := range base {
		require.Empty(t, res.keys, "case %s", name)
	}

	// Classes that stay unchanged: the annotation has no code and Big has
	// no room for the call.
	unchanged := map[string]bool{"Cases$Ann.class": true, "Big.class": true}

	for _, nkeys := range []int{1, 2} {
		t.Run(fmt.Sprintf("keys=%d", nkeys), func(t *testing.T) {
			inst := filepath.Join(dir, fmt.Sprintf("inst%d", nkeys))
			require.NoError(t, os.CopyFS(inst, os.DirFS(orig)))

			// key -> Class.method
			methods := make(map[uint64]string)
			next := uint64(1)
			for _, class := range classfileRewritten(t, orig) {
				out := filepath.Join(inst, class)
				cmd := exec.Command(driver, filepath.Join(orig, class), out,
					strconv.Itoa(nkeys), strconv.FormatUint(next, 10))
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				output, err := cmd.Output()

				var exit *exec.ExitError
				if errors.As(err, &exit) && exit.ExitCode() == 2 {
					require.True(t, unchanged[class], "%s is not rewritten", class)
					continue
				}
				require.NoError(t, err, "%s: %s", class, stderr.String())
				require.False(t, unchanged[class], "%s is rewritten", class)

				for line := range strings.SplitSeq(strings.TrimRight(string(output), "\n"), "\n") {
					fields := strings.Split(line, "\t")
					require.Len(t, fields, 3, "unexpected driver line %q", line)
					key, err := strconv.ParseUint(fields[0], 10, 64)
					require.NoError(t, err)
					require.Equal(t, next, key)
					methods[key] = strings.TrimSuffix(class, ".class") + "." + fields[1]
					next++
				}

				// the new class file must be still readable
				javap, err := exec.Command("javap", "-v", "-p", out).CombinedOutput()
				require.NoError(t, err, "%s: %s", class, string(javap))
			}

			// Class initializer, native and abstract methods are skipped.
			for _, method := range methods {
				require.NotContains(t, method, "<clinit>")
				require.NotEqual(t, "Cases.nativeMethod", method)
				require.NotEqual(t, "Cases$Abs.a", method)
			}

			// The rewritten classes pass the bytecode verification, give
			// the same results and call the hook nkeys times at the entry
			// of each method.
			got := classfileMain(t, inst)
			require.Len(t, got, len(classfileCalls))
			for name, calls := range classfileCalls {
				require.Equal(t, base[name].result, got[name].result, "case %s", name)

				var want []string
				for _, call := range calls {
					for range nkeys {
						want = append(want, call)
					}
				}
				var have []string
				for i, key := range got[name].keys {
					have = append(have, methods[key])
					// keys of one method go in sequence
					if i%nkeys != 0 {
						require.Equal(t, got[name].keys[i-1]+1, key, "case %s", name)
					}
				}
				require.Equal(t, want, have, "case %s", name)
			}
		})
	}
}

// TestClassfileMalformed runs the rewriter on broken class files. It must
// either rewrite them or keep them unchanged, the sanitizers the driver
// is built with fail the test for the rest.
func TestClassfileMalformed(t *testing.T) {
	classfileTools(t, "make", "cc", "javac")
	classfileJDK(t, "javac")
	dir := t.TempDir()
	driver := classfileDriver(t, dir)
	orig := classfileCompile(t, dir)

	for _, class := range classfileRewritten(t, orig) {
		// Big takes too long and has just one kind of instruction.
		if class == "Big.class" {
			continue
		}
		t.Run(class, func(t *testing.T) {
			output, err := exec.Command(driver, "--fuzz", filepath.Join(orig, class)).CombinedOutput()
			require.NoError(t, err, string(output))
		})
	}
}
