#!/bin/bash

# ==============================================================================
# Tetragon Stress Test Generator - OOO & High Volume
# ==============================================================================
# How to use: ./stress_test_generator.sh [NUMBER OF PROCESSES]
# Example: ./stress_test_generator.sh 100
# ==============================================================================

ITERATIONS=${1:-10} # 10 iterations by default
OUTPUT_FILE="stress_events_ooo.jsonl"
TIMESTAMP_BASE=$(date +%s)
ROOT_PARENT_ID="Y2lsaXVtLXJvb3QtcGFyZW50OjE="

> $OUTPUT_FILE

# Set ktime depending on the OS (Linux/macOS)
get_time() {
    local offset=$1 # Offset en segundos desde el inicio base
    local target_time=$((TIMESTAMP_BASE + offset))
    local os_name=$(uname -s)

    if [[ "$os_name" == "Darwin" ]]; then
        date -u -r "$target_time" +"%Y-%m-%dT%H:%M:%SZ"
    else
        date -u -d "@$target_time" +"%Y-%m-%dT%H:%M:%SZ"
    fi
}

cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_EXEC",
  "ktime": "$(get_time 0)",
  "event": {
    "exec_id": "$ROOT_PARENT_ID",
    "pid": 1,
    "binary": "/usr/bin/containerd",
    "arguments": "shim",
    "pod": { "name": "system", "namespace": "kube-system" }
  }
}
EOF

# Load Generation Loop
# For each iteration, we create a full lifecycle cycle with OOO events.
for (( i=1; i<=ITERATIONS; i++ ))
do
    CURRENT_ID=$(echo "process-test-$i" | base64) 
    CURRENT_PID=$((2000 + i))
    
# Relative times for this specific process
# To prevent all events from occurring in the exact same second, we add a small offset based on 'i'
    T_START=$((i + 1))
    T_ACTION=$((i + 3))
    T_EXIT=$((i + 5))
    T_OOO_KPROBE=$((i + 2)) # It happened before the exit.
    T_OOO_LSM=$((i + 4))    # It happened before the exit.

cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_EXEC",
  "ktime": "$(get_time $T_START)",
  "event": {
    "exec_id": "$CURRENT_ID",
    "pid": $CURRENT_PID,
    "binary": "/usr/bin/stress-ng",
    "arguments": "--cpu 1 --timeout 60s",
    "parent_exec_id": "$ROOT_PARENT_ID",
    "pod": { "name": "stress-pod-$i", "namespace": "default" }
  },
  "parent": { "exec_id": "$ROOT_PARENT_ID" }
}
EOF

cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_TRACEPOINT",
  "ktime": "$(get_time $T_ACTION)",
  "event": {
    "exec_id": "$CURRENT_ID",
    "pid": $CURRENT_PID,
    "binary": "/usr/bin/stress-ng"
  },
}
EOF

# PROCESS_EXIT
cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_EXIT",
  "ktime": "$(get_time $T_EXIT)",
  "event": {
    "exec_id": "$CURRENT_ID",
    "pid": $CURRENT_PID,
    "binary": "/usr/bin/stress-ng"
  }
}
EOF

# PROCESS_KPROBE (OOO Event - Late) ---
# Actual ktime: T_OOO_KPROBE (less than T_EXIT)
# File position: AFTER the Exit.
cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_KPROBE",
  "ktime": "$(get_time $T_OOO_KPROBE)",
  "event": {
    "exec_id": "$CURRENT_ID",
    "pid": $CURRENT_PID,
    "binary": "/usr/bin/stress-ng"
  }
}
EOF

# --- E. PROCESS_LSM (OOO Event - Security-Critical) ---
# Actual ktime: T_OOO_LSM (less than T_EXIT)
# File position: AFTER the Exit.
cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_LSM",
  "ktime": "$(get_time $T_OOO_LSM)",
  "event": {
    "exec_id": "$CURRENT_ID",
    "pid": $CURRENT_PID,
    "binary": "/usr/bin/stress-ng"
  }
}
EOF

done

echo "[SUCCESS] File generated successfully."
echo "Total load: $((ITERATIONS * 5 + 1)) JSON events in total."