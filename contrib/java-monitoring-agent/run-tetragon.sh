#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

set -euo pipefail

agent_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$agent_dir/../.." && pwd)
deps_dir=${JAVA_MONITOR_DEPS_DIR:-$agent_dir/build/deps}
env_file=$agent_dir/build/java-monitoring.env
asm_version=${ASM_VERSION:-9.7}
asm_jar=${ASM_JAR:-$deps_dir/asm-$asm_version.jar}
asm_commons_jar=${ASM_COMMONS_JAR:-$deps_dir/asm-commons-$asm_version.jar}
jdk_image=${JAVA_MONITOR_JDK_IMAGE:-eclipse-temurin:22-jdk}

download_jar() {
	local artifact=$1
	local destination=$2
	local temporary=${destination}.download

	if [[ -f $destination ]]; then
		return
	fi
	if ! command -v curl >/dev/null 2>&1; then
		echo "curl is required to download $artifact $asm_version" >&2
		exit 1
	fi

	echo "Downloading $artifact $asm_version"
	curl --fail --location --silent --show-error \
		-o "$temporary" \
		"https://repo.maven.apache.org/maven2/org/ow2/asm/$artifact/$asm_version/$artifact-$asm_version.jar"
	mv -- "$temporary" "$destination"
}

find_java_home() {
	local candidate=${JAVA_HOME:-}

	if [[ -z $candidate ]] && command -v javac >/dev/null 2>&1; then
		candidate=$(dirname -- "$(dirname -- "$(readlink -f -- "$(command -v javac)")")")
	fi
	printf '%s' "$candidate"
}

has_jdk_22() {
	local candidate=$1
	local version major

	[[ -x $candidate/bin/javac && -x $candidate/bin/java ]] || return 1
	version=$($candidate/bin/javac -version 2>&1)
	major=${version#javac }
	major=${major%%.*}
	[[ $major =~ ^[0-9]+$ && $major -ge 22 ]]
}

mkdir -p -- "$deps_dir" "$agent_dir/build"
download_jar asm "$asm_jar"
download_jar asm-commons "$asm_commons_jar"
asm_jar=$(readlink -f -- "$asm_jar")
asm_commons_jar=$(readlink -f -- "$asm_commons_jar")

echo "Building Tetragon, its BPF programs, and tetra"
make -C "$repo_root" tetragon tetragon-bpf tetra

java_home=$(find_java_home)
if has_jdk_22 "$java_home"; then
	echo "Building the Java agent with $java_home"
	make -C "$agent_dir" \
		JAVA_HOME="$java_home" \
		ASM_JAR="$asm_jar" \
		ASM_COMMONS_JAR="$asm_commons_jar" \
		all sample
	java_runtime=native
else
	if ! command -v docker >/dev/null 2>&1; then
		echo "JDK 22+ was not found and Docker is unavailable." >&2
		echo "Set JAVA_HOME to a JDK 22+ installation and retry." >&2
		exit 1
	fi

	echo "JDK 22+ not found locally; building with $jdk_image"
	docker run --rm \
		--user "$(id -u):$(id -g)" \
		-v "$agent_dir:/agent" \
		-v "$asm_jar:/deps/asm.jar:ro" \
		-v "$asm_commons_jar:/deps/asm-commons.jar:ro" \
		-w /agent \
		"$jdk_image" \
		bash -euc '
			rm -rf build/classes build/sample
			mkdir -p build/classes build/sample
			javac --release 22 -cp /deps/asm.jar:/deps/asm-commons.jar \
				-d build/classes $(find src -name "*.java")
			printf "Premain-Class: io.tetragon.javaagent.TetragonAgent\nCan-Redefine-Classes: false\nCan-Retransform-Classes: false\n" \
				> build/classes/MANIFEST.MF
			jar --create --file tetragon-java-monitoring-agent.jar \
				--manifest build/classes/MANIFEST.MF -C build/classes .
			javac --release 22 -d build/sample sample/Sample.java
		'
	java_runtime=docker
fi

{
	printf 'JAVA_MONITOR_REPO_ROOT=%q\n' "$repo_root"
	printf 'JAVA_MONITOR_AGENT_DIR=%q\n' "$agent_dir"
	printf 'JAVA_MONITOR_RUNTIME=%q\n' "$java_runtime"
	printf 'JAVA_MONITOR_JAVA_HOME=%q\n' "$java_home"
	printf 'JAVA_MONITOR_ASM_JAR=%q\n' "$asm_jar"
	printf 'JAVA_MONITOR_ASM_COMMONS_JAR=%q\n' "$asm_commons_jar"
	printf 'JAVA_MONITOR_JDK_IMAGE=%q\n' "$jdk_image"
} > "$env_file"

echo "Java environment written to $env_file"
echo "Starting Tetragon; run $agent_dir/run-sample.sh in another terminal"
exec sudo "$repo_root/tetragon" \
	--bpf-lib "$repo_root/bpf/objs" \
	--enable-ancestors=base,java \
	"$@"
