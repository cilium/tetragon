#!/bin/bash

# ==============================================================================
# Tetragon Synthetic Event Generator - Cross-Platform (Linux/macOS)
# ==============================================================================
# Objective: Generate a JSONL event stream to test race conditions
#           and out-of-order (OOO) events in Tetragon’s ProcessCache.
# ==============================================================================

OUTPUT_FILE="synthetic_events.jsonl"
echo "[INFO] Starting scenario generation in file: $OUTPUT_FILE"

# 1. We define constant IDs (Base64) to maintain referential integrity.
PARENT_EXEC_ID="Y2lsaXVtLXRlc3QtcGFyZW50OjE="
CHILD_EXEC_ID="Y2lsaXVtLXRlc3QtY2hpbGQ6Mg=="

# 2. We capture the base time (Epoch seconds) at the start of execution.
ktime_BASE=$(date +%s)

# 3. Smart function to format dates based on the detected OS. (Linux/macOS)
get_time() {
    local offset=$1
    local target_time=$((ktime_BASE + offset))
    local os_name=$(uname -s)
        # Mac System
    if [[ "$os_name" == "Darwin" ]]; then
        date -u -r "$target_time" +"%Y-%m-%dT%H:%M:%SZ"
    else
        # Linux system (GNU date)
        date -u -d "@$target_time" +"%Y-%m-%dT%H:%M:%SZ"
    fi
}

echo "[INFO] Detected OS: $(uname -s)"
echo "[INFO] Events..."

# --- EVENT 1: EXEC father process (T=0) ---
cat <<EOF > $OUTPUT_FILE
{
  "type": "PROCESS_EXEC",
  "ktime": "$(get_time 0)",
  "event": {
    "exec_id": "$PARENT_EXEC_ID",
    "pid": 1000,
    "binary": "/usr/bin/nginx",
    "arguments": "-g 'daemon off;'",
    "pod": { "name": "nginx-pod", "namespace": "default" }
  }
}
EOF

# --- EVENT 2: EXEC child process (T=5) ---
cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_EXEC",
  "ktime": "$(get_time 5)",
  "event": {
    "exec_id": "$CHILD_EXEC_ID",
    "pid": 1001,
    "binary": "/bin/bash",
    "parent_exec_id": "$PARENT_EXEC_ID",
    "pod": { "name": "nginx-pod", "namespace": "default" }
  },
  "parent": { "exec_id": "$PARENT_EXEC_ID" }
}
EOF

# --- EVENT 3: EXIT child process (T=10) ---
# The process officially ends here because the process type is: PROCESS_EXIT
cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_EXIT",
  "ktime": "$(get_time 10)",
  "event": {
    "exec_id": "$CHILD_EXEC_ID",
    "pid": 1001,
    "binary": "/bin/bash"
  }
}
EOF

# --- EVENT 4: KPROBE (Open file) from the Child (T=8) ---
# *** OOO (Out-Of-Order) SIMULATION ***
# This event has ktime T=8 (before the exit), but it is written at the end of the file.
# This tests whether the ProcessCache can handle an "old" event from a process that has already reported "exit."
cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_KPROBE",
  "ktime": "$(get_time 8)",
  "event": {
    "exec_id": "$CHILD_EXEC_ID",
    "pid": 1001,
    "binary": "/bin/bash"
  }
}
EOF

cat <<EOF >> $OUTPUT_FILE
{
  "type": "PROCESS_TRACEPOINT",
  "ktime": "$(get_time 9)",
  "event": {
    "exec_id": "$CHILD_EXEC_ID",
    "pid": 1001,
    "binary": "/bin/bash"
  },
}
EOF

echo "[SUCCESS] File generated successfully."
echo "---------------------------------------------------"
echo "Preview of the generated content:"
cat $OUTPUT_FILE
echo "---------------------------------------------------"