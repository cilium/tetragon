#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

# Run the Coccinelle checks (*.cocci) in this directory on the BPF code, and
# fail if any of them reports something. Requires spatch, with Python support,
# see Dockerfile.coccinelle and the check-cocci make target.
#
# Each check is first run on its test cases, tests/<check>.c if it exists: the
# lines ending with a "// REPORT" comment must be reported, and nothing else.

set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$dir/../.." && pwd)

# spatch writes temporary files in its working directory with --jobs, while the
# sources can be read-only.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# spatch_report <cocci> <spatch arguments>: print the reports of a check, with
# paths relative to the repository.
spatch_report() {
	local cocci=$1 out
	shift
	if ! out=$(spatch --very-quiet -D report --no-includes \
		--macro-file-builtins "$dir/macros.h" \
		--sp-file "$cocci" "$@" 2>&1); then
		echo "$out" >&2
		echo "spatch failed on $(basename "$cocci")" >&2
		exit 1
	fi
	if [ -n "$out" ]; then
		echo "$out" | sed "s#^$root/##" | sort
	fi
}

ret=0

for cocci in "$dir"/*.cocci; do
	test="$dir/tests/$(basename "$cocci" .cocci).c"
	if [ ! -f "$test" ]; then
		continue
	fi
	name=${test#"$root/"}
	expected=$(grep -n '// REPORT$' "$test" | cut -d: -f1 | sort || true)
	actual=$(spatch_report "$cocci" "$test" | cut -d: -f2 | sort)
	missing=$(comm -23 <(echo "$expected") <(echo "$actual"))
	unexpected=$(comm -13 <(echo "$expected") <(echo "$actual"))
	for line in $missing; do
		echo "$name:$line: missing report"
		ret=1
	done
	for line in $unexpected; do
		echo "$name:$line: unexpected report"
		ret=1
	done
done

for cocci in "$dir"/*.cocci; do
	# The generated vmlinux headers don't contain any program, skip them.
	out=$(spatch_report "$cocci" --include-headers \
		--ignore "$root/bpf/include/vmlinux" \
		--jobs "$(nproc)" --dir "$root/bpf")
	if [ -n "$out" ]; then
		echo "$out"
		ret=1
	fi
done

if [ $ret -ne 0 ]; then
	echo "Coccinelle checks failed, see the contrib/coccinelle/*.cocci files for details."
fi
exit $ret
