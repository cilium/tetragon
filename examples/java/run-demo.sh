#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

# Java monitoring demo, see README.md.
#
# Run it as regular user. Everything is built and the demo JVM runs as that
# user, only Tetragon itself is started through sudo.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# Root needs no sudo, but it also needs the whole build toolchain.
SUDO=(sudo)
if [[ $(id -u) -eq 0 ]]; then
    SUDO=()
fi

for tool in make go javac java "${SUDO[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required command not found: $tool" >&2
        exit 1
    fi
done

RUN_DIR=$(mktemp -d /tmp/tetragon-java-demo.XXXXXX)
# The JVM connects to the agent socket in here.
chmod 0755 "$RUN_DIR"

LOG="$RUN_DIR/tetragon.log"

cleanup() {
    # The demo JVM.
    local pids
    pids=$(jobs -p)
    if [[ -n "$pids" ]]; then
        kill $pids 2>/dev/null || true
        wait 2>/dev/null || true
    fi
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT

INTERRUPTED=
trap 'INTERRUPTED=1' INT TERM

echo "Building Tetragon, its BPF programs, tetra and the JVMTI agent..."
make -C "$ROOT" LOCAL_CLANG=1 tetragon-bpf tetragon tetra tetragon-jvmti-agent

javac -d "$RUN_DIR" "$ROOT/examples/java/TetragonJavaDemo.java"

# Ask for the sudo password now, before anything is started.
if [[ ${#SUDO[@]} -gt 0 ]]; then
    echo "Tetragon needs root, checking sudo..."
    sudo -v
fi

# JDKs that support this option require it to permit dynamic agent loading.
# On JDKs where it is not recognized, keep the JVM's default behavior.
JAVA_AGENT_FLAGS=()
if java -XX:+EnableDynamicAgentLoading -version >/dev/null 2>&1; then
    JAVA_AGENT_FLAGS=(-XX:+EnableDynamicAgentLoading)
fi

java "${JAVA_AGENT_FLAGS[@]}" -cp "$RUN_DIR" \
    TetragonJavaDemo tetragon-java-demo &
echo "Started demo JVM (pid $!); policy target token: tetragon-java-demo"

echo "Starting Tetragon, its log goes to $LOG"
echo
echo "To see the Java events, run this in another terminal:"
echo
echo "  $ROOT/tetra getevents -o compact --event-types PROCESS_JAVA"
echo
echo "Press Ctrl-C to stop."

# The agent library is used straight from the build, so there is nothing
# to install.
rc=0
"${SUDO[@]}" "$ROOT/tetragon" \
    --bpf-lib "$ROOT/bpf/objs" \
    --tracing-policy "$ROOT/examples/java/demo-tracingpolicy.yaml" \
    --java-agent-path "$ROOT/pkg/javaattach/agent/tetragon-jvmti.so" \
    --java-agent-socket-path "$RUN_DIR/java.sock" \
    >"$LOG" 2>&1 || rc=$?

if [[ -z "$INTERRUPTED" && $rc -ne 0 ]]; then
    echo "Tetragon failed (exit code $rc), the end of its log:" >&2
    tail -n 20 "$LOG" >&2
    exit "$rc"
fi
