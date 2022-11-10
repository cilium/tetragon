#!/usr/bin/env bash
#
# Script to verify all Tetragon programs by loading them with bpftool.
#
set -u
shopt -s nullglob

RED="\033[31m"
BLUEUNDER="\033[34;4m"
GREEN="\033[32m"
NOCOLOR="\033[0m"
TETRAGONDIR=/var/lib/tetragon
DEBUG=0

usage() {
	echo "usage: verify.sh [-d] [TETRAGONDIR]"
	echo "-d to run bpftool with -d and dump number of processed instructions"
	exit 1
}

if [ $# -ge 1 ]; then
	if [ "$1" == "-d" ]; then
		DEBUG=1
		shift 1
	fi

	if [ $# -ge 1 ]; then
		[ -d $1 ] || usage
		TETRAGONDIR=$1
	fi
fi

PINDIR=/sys/fs/bpf/tetragon-verify
mkdir -p "$PINDIR"
cleanup() {
	rm -rf "$PINDIR"
}
trap cleanup EXIT

STATUS=0

for obj in "$TETRAGONDIR"/*.o; do
	B=$(basename "$obj")

    # Alignchecker is not a bpf program, so ignore it
	if [[ "$B" == bpf_alignchecker* ]]; then
		continue
	fi

    # Globals is just for testing, so ignore it
	if [[ "$B" == bpf_globals* ]]; then
		continue
	fi

    # Generic tracepoint needs more complex userspace logic to load, so ignore it
	if [[ "$B" == bpf_generic_tracepoint* ]]; then
		continue
	fi

    # Multi kprobe support is still not widely around, skip the object
	if [[ "$B" == bpf_multi_* ]]; then
		continue
	fi

    # skip v6.0 objects check, because it is still not widely around
	if [[ "$B" == *60.o ]]; then
		continue
	fi

	echo -e -n "Verifying $BLUEUNDER$obj$NOCOLOR... "
	OUT="/tmp/tetragon-verify-$B"

	FLAGS=""
	[ "$DEBUG" -eq 1 ] && FLAGS="-d"
	bpftool help 2>&1 | grep -q -- "--legacy" && FLAGS="$FLAGS --legacy"

	bpftool $FLAGS prog loadall "$obj" "$PINDIR" &> "$OUT"
	if [ $? -ne 0 ]; then
		echo -e "${RED}Failed!${NOCOLOR}"
		awk '/^func/ { in_func=1 } /^;/ { if (in_func) { print $0; print "..."; exit } }' < "$OUT"
		tail -20 "$OUT"
		echo "Full output left in $OUT"
		STATUS=1
	else
		echo -e "${GREEN}OK${NOCOLOR}"
		awk '
/^func/ { in_func=1 }
/^;/ { if (in_func) { print "  " $0; in_func=0; } }
/^verification time/ { verify_lines=3 }
/^/ { if (verify_lines) { verify_lines -= 1; print "  " $0 } }' < "$OUT"
		rm "$OUT"
	fi
	echo
	rm -rf "$PINDIR"
done

exit "$STATUS"

