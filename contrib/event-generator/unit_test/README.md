# Tetragon Synthetic Event Generator (OOO Scenarios)

This script (test_ooo_scenario_v1.sh) generates a synthetic JSONL event stream designed to test race conditions and Out-Of-Order (OOO) handling within Tetragon's ProcessCache.


## Objective

To validate that Tetragon correctly processes events that arrive late (after the process has already reported an EXIT), preventing memory leaks and ensuring data integrity.


## The Scenario

The script generates a timeline that deliberately contradicts the file order to simulate network/buffer latency.

1. Start (T=00): Parent process (Nginx) starts.
2. Start (T=05): Child process (Bash) starts.
3. EXIT (T=10): Child process dies. The lifecycle is officially over.
Late Event (T=08): We inject a KPROBE event and PROCESS_TRACEPOINT event that occurred before the death, but it is written at the end of the file.

## The Challenge: 
The ProcessCache must not discard this late event even though the process is marked as "Dead" (EXIT). and wait for (GO) garbage collector. action once the process is (0)


## Usage

Make the script executable and run it. It automatically detects your OS (Linux/macOS) to format timestamps correctly.

```bash
chmod +x test_ooo_scenario_v1.sh
./test_ooo_scenario_v1.sh
```

## Expected Output

The script generates a file named synthetic_events.jsonl. Notice the last event (PROCESS_KPROBE and PROCESS_TRACEPOINT) appears at the bottom but has an earlier timestamp than the PROCESS_EXIT.

```json
{
  "type": "PROCESS_EXEC",
  "ktime": "2026-01-13T22:40:30Z",
  "event": {
    "exec_id": "Y2lsaXVtLXRlc3QtcGFyZW50OjE=",
    "pid": 1000,
    "binary": "/usr/bin/nginx",
    "arguments": "-g 'daemon off;'",
    "pod": { "name": "nginx-pod", "namespace": "default" }
  }
}
{
  "type": "PROCESS_EXEC",
  "ktime": "2026-01-13T22:40:35Z",
  "event": {
    "exec_id": "Y2lsaXVtLXRlc3QtY2hpbGQ6Mg==",
    "pid": 1001,
    "binary": "/bin/bash",
    "parent_exec_id": "Y2lsaXVtLXRlc3QtcGFyZW50OjE=",
    "pod": { "name": "nginx-pod", "namespace": "default" }
  },
  "parent": { "exec_id": "Y2lsaXVtLXRlc3QtcGFyZW50OjE=" }
}
{
  "type": "PROCESS_EXIT",
  "ktime": "2026-01-13T22:40:40Z",
  "event": {
    "exec_id": "Y2lsaXVtLXRlc3QtY2hpbGQ6Mg==",
    "pid": 1001,
    "binary": "/bin/bash"
  }
}
{
  "type": "PROCESS_KPROBE",
  "ktime": "2026-01-13T22:40:38Z",
  "event": {
    "exec_id": "Y2lsaXVtLXRlc3QtY2hpbGQ6Mg==",
    "pid": 1001,
    "binary": "/bin/bash"
  }
}
{
  "type": "PROCESS_TRACEPOINT",
  "ktime": "2026-01-13T22:40:39Z",
  "event": {
    "exec_id": "Y2lsaXVtLXRlc3QtY2hpbGQ6Mg==",
    "pid": 1001,
    "binary": "/bin/bash"
  },
}

```