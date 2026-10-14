#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
if [[ $(id -u) -ne 0 ]]; then
    echo "Run this script as root, for example: sudo $0" >&2
    exit 1
fi
for tool in make javac java; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required command not found: $tool" >&2
        exit 1
    fi
done

RUN_DIR=$(mktemp -d /tmp/tetragon-java-demo.XXXXXX)
chmod 0755 "$RUN_DIR"
JAVA_PID=
cleanup() {
    if [[ -n "$JAVA_PID" ]]; then
        kill "$JAVA_PID" 2>/dev/null || true
        wait "$JAVA_PID" 2>/dev/null || true
    fi
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT INT TERM

echo "Building Tetragon, its BPF programs, and the JVMTI agent..."
make -C "$ROOT" LOCAL_CLANG=1 tetragon-bpf tetragon tetragon-jvmti-agent
install -D -m 0755 "$ROOT/pkg/javaattach/agent/tetragon-jvmti.so" \
    /usr/lib/tetragon/tetragon-jvmti.so

javac -d "$RUN_DIR" "$ROOT/examples/java/TetragonJavaDemo.java"

# JDKs that support this option require it to permit dynamic agent loading.
# On JDKs where it is not recognized, keep the JVM's default behavior.
JAVA_AGENT_FLAGS=()
if java -XX:+EnableDynamicAgentLoading -version >/dev/null 2>&1; then
    JAVA_AGENT_FLAGS=(-XX:+EnableDynamicAgentLoading)
fi

# Run the JVM as the invoking user when called through sudo. Tetragon remains
# root so it can attach to the JVM and load its BPF programs.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] && command -v runuser >/dev/null 2>&1; then
    runuser -u "$SUDO_USER" -- \
        java "${JAVA_AGENT_FLAGS[@]}" -cp "$RUN_DIR" \
        TetragonJavaDemo tetragon-java-demo &
else
    java "${JAVA_AGENT_FLAGS[@]}" -cp "$RUN_DIR" \
        TetragonJavaDemo tetragon-java-demo &
fi
JAVA_PID=$!
echo "Started demo JVM (pid $JAVA_PID); policy target token: tetragon-java-demo"
echo "Tetragon event output follows. Press Ctrl-C to stop both processes."

"$ROOT/tetragon" \
    --bpf-lib "$ROOT/bpf/objs" \
    --tracing-policy "$ROOT/examples/java/demo-tracingpolicy.yaml" \
    --java-agent-socket-path "$RUN_DIR/java.sock"
