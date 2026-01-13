# Tetragon Stress Test Generator (High Volume & OOO)

This script (stress_test_generator.sh) generates a massive stream of synthetic JSONL events. It is designed to perform Load Testing and Stress Testing on Tetragon's ProcessCache, specifically targeting memory management and Out-Of-Order (OOO) event handling at scale.

## Objective

To simulate a high-load environment where thousands of processes are created, execute actions, and die, while simultaneously injecting late events (OOO) for every single process. This validates:

* Garbage Collection: Ensures memory is freed correctly after complex OOO scenarios.
Performance: Measures ingestion speed and cache stability under pressure.

## The Scenario (The Loop):

The script creates a "Root Parent" process (PID 1) and then enters a loop to generate N child processes. For each iteration/process:

## Testing process: 
Start (EXEC): A unique child process (stress-ng) is born, linked to the Root Parent.
Action (TRACEPOINT): The process performs a standard system activity.
Death (EXIT): The process officially terminates.
Late Events (OOO):
A PROCESS_KPROBE event (timestamped before death) arrives after the exit.
A PROCESS_LSM event (security check) arrives after the exit.

## The Challenge: 
Tetragon must correctly correlate thousands of late events to their respective (now dead) processes without crashing or leaking memory.

## Usage
Run the script passing the number of processes you want to simulate as an argument.

```bash
chmod +x stress_test_generator.sh

# Generate 10 processes (Default)
./stress_test_generator.sh

# Generate 100 processes (Load Test)
./stress_test_generator.sh 100

# Generate 10,000 processes (Stress/Memory Leak Test)
./stress_test_generator.sh 10000
```

## Expected Output

The script generates a file named stress_events_ooo.jsonl.


Total Events: (Iterations * 5) + 1
Structure: You will see a repeating pattern of EXEC -> TRACEPOINT -> EXIT -> KPROBE (Late) -> LSM (Late).

## Output example: 
```json
{
  "type": "PROCESS_EXEC",
  "ktime": "2026-01-13T22:51:14Z",
  "event": {
    "exec_id": "Y2lsaXVtLXJvb3QtcGFyZW50OjE=",
    "pid": 1,
    "binary": "/usr/bin/containerd",
    "arguments": "shim",
    "pod": { "name": "system", "namespace": "kube-system" }
  }
}
{
  "type": "PROCESS_EXEC",
  "ktime": "2026-01-13T22:51:16Z",
  "event": {
    "exec_id": "cHJvY2Vzcy10ZXN0LTEK",
    "pid": 2001,
    "binary": "/usr/bin/stress-ng",
    "arguments": "--cpu 1 --timeout 60s",
    "parent_exec_id": "Y2lsaXVtLXJvb3QtcGFyZW50OjE=",
    "pod": { "name": "stress-pod-1", "namespace": "default" }
  },
  "parent": { "exec_id": "Y2lsaXVtLXJvb3QtcGFyZW50OjE=" }
}
{
  "type": "PROCESS_TRACEPOINT",
  "ktime": "2026-01-13T22:51:18Z",
  "event": {
    "exec_id": "cHJvY2Vzcy10ZXN0LTEK",
    "pid": 2001,
    "binary": "/usr/bin/stress-ng"
  },
}
{
  "type": "PROCESS_EXIT",
  "ktime": "2026-01-13T22:51:20Z",
  "event": {
    "exec_id": "cHJvY2Vzcy10ZXN0LTEK",
    "pid": 2001,
    "binary": "/usr/bin/stress-ng"
  }
}
{
  "type": "PROCESS_KPROBE",
  "ktime": "2026-01-13T22:51:17Z",
  "event": {
    "exec_id": "cHJvY2Vzcy10ZXN0LTEK",
    "pid": 2001,
    "binary": "/usr/bin/stress-ng"
  }
}
{
  "type": "PROCESS_LSM",
  "ktime": "2026-01-13T22:51:19Z",
  "event": {
    "exec_id": "cHJvY2Vzcy10ZXN0LTEK",
    "pid": 2001,
    "binary": "/usr/bin/stress-ng"
  }
}

```