#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

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

echo "Compiling Java agent and sample..."
make -C "$SCRIPT_DIR" sample \
	JAVA_HOME="$JAVA_HOME" \
	ASM_JAR="$ASM_JAR" \
	ASM_COMMONS_JAR="$ASM_COMMONS_JAR"

AGENT_JAR=${AGENT_JAR:-$SCRIPT_DIR/tetragon-java-monitoring-agent.jar}
SAMPLE_CLASS=${SAMPLE_CLASS:-sample.Sample}
TARGET_METHOD=${TARGET_METHOD:-work}
JAVA_RING_PATH=${JAVA_RING_PATH:-/var/run/tetragon/java.ring}

if [[ ! -f "$JAVA_RING_PATH" ]]; then
	echo "Java IPC ring file not found: $JAVA_RING_PATH" >&2
	echo "Start Tetragon with --java-ipc-path first, e.g. via ./run-tetragon.sh" >&2
	exit 1
fi

echo "Running $SAMPLE_CLASS with the Tetragon Java agent (method=$TARGET_METHOD, ring=$JAVA_RING_PATH)..."
exec "$JAVA_HOME/bin/java" --enable-native-access=ALL-UNNAMED \
	"$@" \
	-javaagent:"$AGENT_JAR"=class="$SAMPLE_CLASS",method="$TARGET_METHOD",path="$JAVA_RING_PATH" \
	-cp "$SCRIPT_DIR/build/sample:$ASM_JAR:$ASM_COMMONS_JAR" \
	"$SAMPLE_CLASS"
