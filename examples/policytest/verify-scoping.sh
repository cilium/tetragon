#!/usr/bin/env bash
#
# Check that --pod-selector confines a policy to the labelled pod: load the
# same kprobe policy scoped and unscoped, count events per pod from
# scoping-check.yaml. Scoped: probe > 0, control = 0. Unscoped: control > 0,
# which proves the control can detect a leak.
#
# Usage: examples/policytest/verify-scoping.sh [kube-context]

set -euo pipefail

CTX="${1:-}"
KUBECTL=(kubectl)
[ -n "$CTX" ] && KUBECTL+=(--context="$CTX")

NS=tetragon-policytest
AGENT_NS="${AGENT_NS:-tetragon}"
BIN=/run/tetragon/policytest-progs/lseek-pipe
WINDOW="${WINDOW:-10}"
LOG=/var/log/tetragon/tetragon.log
MANIFEST="$(dirname "$0")/scoping-check.yaml"

policy() { # $1: "scoped" | "unscoped"
	cat <<-YAML
	apiVersion: cilium.io/v1alpha1
	kind: TracingPolicy
	metadata:
	  name: scoping-check
	spec:
	$( [ "$1" = scoped ] && printf '  podSelector:\n    matchLabels:\n      app: tetragon-policytest\n' )
	  kprobes:
	  - call: "sys_lseek"
	    syscall: true
	    args:
	    - index: 0
	      type: "int"
	    selectors:
	    - matchBinaries:
	      - operator: "In"
	        values:
	        - "$BIN"
	YAML
}

# the agent on the probe's node: the pods share its hostPath and its log
agent_pod() {
	local node
	node=$("${KUBECTL[@]}" get pod -n "$NS" policytest-probe -o jsonpath='{.spec.nodeName}')
	"${KUBECTL[@]}" get pod -n "$AGENT_NS" -l app.kubernetes.io/name=tetragon \
		--field-selector "spec.nodeName=$node" -o jsonpath='{.items[0].metadata.name}'
}

agent_exec() { "${KUBECTL[@]}" exec -n "$AGENT_NS" "$AGENT_POD" -c tetragon -- "$@"; }

count_events() { # stdin: jsonl; prints "<probe> <control>"
	python3 -c '
import sys, json
ns = sys.argv[1]
n = {"policytest-probe": 0, "policytest-control": 0}
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    k = e.get("process_kprobe")
    if not k or k.get("policy_name") != "scoping-check": continue
    pod = (k.get("process") or {}).get("pod") or {}
    if pod.get("namespace") != ns: continue
    if pod.get("name") in n: n[pod["name"]] += 1
print(n["policytest-probe"], n["policytest-control"])' "$NS"
}

run() { # $1: scoped|unscoped -> prints "<probe> <control>"
	local mode=$1 before after
	before=$(agent_exec sh -c "stat -c %i $LOG; wc -l < $LOG")
	policy "$mode" | "${KUBECTL[@]}" apply -f - >/dev/null
	sleep "$WINDOW"
	"${KUBECTL[@]}" delete tracingpolicy scoping-check >/dev/null
	# a rotation (new inode) would silently drop part of the window and fake a clean result
	after=$(agent_exec sh -c "stat -c %i $LOG; wc -l < $LOG")
	read -r before_ino before <<<"${before//$'\n'/ }"
	read -r after_ino after <<<"${after//$'\n'/ }"
	if [ "$after_ino" != "$before_ino" ] || [ "$after" -lt "$before" ]; then
		echo "export log rotated during the $mode run; rerun with a smaller WINDOW" >&2
		exit 1
	fi
	agent_exec sh -c "tail -n +$((before + 1)) $LOG" | count_events
}

cleanup() { # best effort: a failure here must not mask the result
	"${KUBECTL[@]}" delete tracingpolicy scoping-check --ignore-not-found >/dev/null || true
	"${KUBECTL[@]}" delete -n "$NS" -f "$MANIFEST" --ignore-not-found >/dev/null || true
}
trap cleanup EXIT

"${KUBECTL[@]}" get ns "$NS" >/dev/null 2>&1 || "${KUBECTL[@]}" create ns "$NS" >/dev/null
"${KUBECTL[@]}" apply -f "$MANIFEST" >/dev/null
"${KUBECTL[@]}" wait -n "$NS" --for=condition=Ready pod/policytest-probe pod/policytest-control --timeout=120s >/dev/null
AGENT_POD=$(agent_pod)
[ -n "$AGENT_POD" ] || { echo "no $AGENT_NS agent pod on the probe's node" >&2; exit 1; }

scoped=$(run scoped)
unscoped=$(run unscoped)
read -r s_probe s_control <<<"$scoped"
read -r u_probe u_control <<<"$unscoped"

printf '\n%-10s %14s %14s\n' "run" "probe events" "control events"
printf '%-10s %14d %14d\n' "scoped"   "$s_probe" "$s_control"
printf '%-10s %14d %14d\n\n' "unscoped" "$u_probe" "$u_control"

rc=0
[ "$s_probe"   -gt 0 ] || { echo "FAIL: scoped run produced no events for the probe pod"; rc=1; }
[ "$s_control" -eq 0 ] || { echo "FAIL: policy leaked to the control pod while scoped"; rc=1; }
[ "$u_control" -gt 0 ] || { echo "FAIL: unscoped run produced no control events, so the control cannot detect a leak"; rc=1; }
[ "$rc" -eq 0 ] && echo "PASS: --pod-selector confined the policy to the labelled pod"
exit "$rc"
