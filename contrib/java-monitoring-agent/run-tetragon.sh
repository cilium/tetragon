#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)

if [[ -z "${JAVA_HOME:-}" ]]; then
	javac_path=$(command -v javac || true)
	if [[ -z "$javac_path" ]]; then
		echo "JAVA_HOME is not set and javac was not found" >&2
		exit 1
	fi
	JAVA_HOME=$(cd -- "$(dirname -- "$(readlink -f "$javac_path")")/.." && pwd)
fi

if [[ ! -x "$JAVA_HOME/bin/javac" || ! -x "$JAVA_HOME/bin/java" ]]; then
	echo "JAVA_HOME must point to a JDK containing bin/java and bin/javac: $JAVA_HOME" >&2
	exit 1
fi

java_major=$(
	"$JAVA_HOME/bin/java" -version 2>&1 |
		sed -n 's/.*version "\([0-9][0-9]*\)\..*/\1/p; s/.*version "\([0-9][0-9]*\)".*/\1/p' |
		head -n 1
)
if [[ -z "$java_major" || "$java_major" -lt 22 ]]; then
	echo "JDK 22 or newer is required (found ${java_major:-unknown})" >&2
	exit 1
fi

ASM_JAR=${ASM_JAR:-$SCRIPT_DIR/build/deps/asm-9.7.jar}
ASM_COMMONS_JAR=${ASM_COMMONS_JAR:-$SCRIPT_DIR/build/deps/asm-commons-9.7.jar}
if [[ ! -f "$ASM_JAR" || ! -f "$ASM_COMMONS_JAR" ]]; then
	echo "ASM dependencies were not found." >&2
	echo "Set ASM_JAR and ASM_COMMONS_JAR, for example:" >&2
	echo "  ASM_JAR=/path/to/asm-9.x.jar" >&2
	echo "  ASM_COMMONS_JAR=/path/to/asm-commons-9.x.jar" >&2
	exit 1
fi

echo "Building Tetragon BPF programs..."
make -C "$REPO_ROOT" tetragon-bpf LOCAL_CLANG="${LOCAL_CLANG:-1}"

echo "Building Tetragon..."
make -C "$REPO_ROOT" tetragon

echo "Compiling Java agent, Java tests, and sample..."
make -C "$SCRIPT_DIR" test sample \
	JAVA_HOME="$JAVA_HOME" \
	ASM_JAR="$ASM_JAR" \
	ASM_COMMONS_JAR="$ASM_COMMONS_JAR"

JAVA_RING_PATH=${JAVA_RING_PATH:-/var/run/tetragon/java.ring}
SERVER_ADDRESS=${SERVER_ADDRESS:-localhost:54321}

echo "Starting Tetragon. Java IPC ring file: $JAVA_RING_PATH"
exec sudo "$REPO_ROOT/tetragon" \
	--bpf-lib "$REPO_ROOT/bpf/objs" \
	--server-address "$SERVER_ADDRESS" \
	--java-ipc-path "$JAVA_RING_PATH" \
	"$@"
