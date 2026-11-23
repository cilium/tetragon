---
title: "Java attachment"
weight: 6
description: "How Tetragon attaches to JVMs and exchanges data with the JVMTI agent"
---

Tetragon can trace method calls inside running Java VMs. A `java:` section
in a TracingPolicy lists the classes and methods to watch, and Tetragon
produces an event each time one of them is entered.

## Overview

Java has no kernel hooks to attach to, so Tetragon injects a small native
agent (a JVMTI library) into the target JVM. The agent rewrites the watched
methods so that they report back to Tetragon.

The whole thing is built from three communication channels:

| Channel | Used for | Direction |
|---|---|---|
| JVM attach interface | one-time: make the JVM load the agent | Tetragon -> JVM |
| Control socket | handshake, policies (which methods to watch) | both ways |
| Shared-memory ring | the actual events (method entered) | JVM -> Tetragon |

```mermaid
sequenceDiagram
  participant T as Tetragon
  participant J as Java agent (in JVM)

  T->>J: 1. Load the agent (JVM attach interface)
  J->>T: 2. Connect and say hello (control socket)
  T->>J: 3. Hand over the shared ring
  T->>J: 4. Send policy: which classes/methods to watch
  J->>T: ack
  Note right of J: agent instruments the matching methods
  J-->>T: 5. Method entered events (ring)
  Note left of T: enrich with process and policy info, emit to gRPC
  T->>J: 6. Policy removed
  J->>T: ack
  Note right of J: instrumentation removed
```

In words:

1. Tetragon finds JVMs that match the policy's targets and asks each one,
   through the standard JVM attach interface, to load the agent library.
2. The agent connects back to Tetragon on a unix socket. Tetragon only
   accepts connections from JVMs it chose to attach to.
3. Tetragon creates a shared-memory ring buffer and gives it to the agent.
4. Tetragon sends the policy: the classes and methods to watch. The agent
   rewrites those methods, including classes that are already loaded.
5. When a watched method runs, the agent writes a small record to the ring.
   Tetragon reads it, adds process and policy information, and emits it as
   an event.
6. When the policy is removed, Tetragon tells the agent, which undoes the
   instrumentation. The library itself stays loaded in the JVM, idle.

The rest of this page goes into detail: how JVMs are found and attached, and
the exact format of every message.

## Example policy

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: java-example
spec:
  java:
    targets:
      # Optional. Select JVMs by executable path and/or by process arguments
      # (every token must appear in one of the arguments). Without
      # executables, any process that has libjvm.so mapped is considered.
      executables:
        - /usr/lib/jvm/java-17-openjdk-amd64/bin/java
      processArgsContains:
        - my-service.jar
    hooks:
      # Exact class, selected methods (all overloads of "handle").
      - class: com.example.RequestHandler
        methods:
          - name: handle
        message: Request handler called
        tags:
          - java
          - request
      # Exact class, a single overload picked by its JVM descriptor.
      - class: com.example.auth.TokenValidator
        methods:
          - name: validate
            descriptor: (Ljava/lang/String;)Z
        message: Token validation
      # Every method of every class under a package prefix.
      - classPrefix: com.example.db.
        message: Database layer call
        tags:
          - java
          - db
```

* `targets` selects the JVMs. Both fields are optional, but a policy needs
  at least one hook or one executable target.
* Each hook needs exactly one of `class` (exact, dotted form, nested classes
  use `$`) or `classPrefix`.
* `methods` limits the hook to the named methods. All overloads match unless
  a `descriptor` is given. Without `methods`, all methods of the matching
  classes are monitored.
* `message` (max 256 characters) and `tags` (max 16) are copied into every
  event produced by that hook. They stay on the Tetragon side and are never
  sent to the JVM.
* Classes in `java/`, `jdk/` and `sun/` cannot be hooked.

A smaller runnable policy is in `examples/java/demo-tracingpolicy.yaml`.

Conventions: all integers are **little-endian**. A `str` is a `u16` length
followed by that many bytes (no NUL terminator). Class names use internal
form (`a/b/C`).

## 1. Message flow

```mermaid
sequenceDiagram
  participant T as Tetragon
  participant J as Java agent (in JVM)

  Note over T,J: 1. Injection (HotSpot Attach protocol)
  T->>J: SIGQUIT + .attach_pid trigger file
  T->>J: "load" request over .java_pid socket (lib path, socket path)
  Note right of J: dlopen, Agent_OnAttach

  Note over T,J: 2. Control channel (SEQPACKET)
  J->>T: connect(java.sock)
  J->>T: HELLO (proto version, vm version)
  T->>J: RING (data_size) + memfd via SCM_RIGHTS
  Note right of J: mmap ring, define TetragonHook, enable ClassFileLoadHook

  Note over T,J: 3. Policy delivery (one command at a time)
  T->>J: HOOK_ADD (class/prefix, methods)
  J->>T: ACK
  T->>J: POLICY_COMMIT (policy id)
  Note right of J: retransform matching classes
  J->>T: ACK

  Note over T,J: 4. Events (shared-memory ring)
  Note right of J: hooked method runs, TetragonHook.enter(key)
  J-->>T: METHOD_DEF (once per method)
  J-->>T: METHOD_ENTRY (key, ktime, tid)
  Note left of T: drain ring, enrich, emit ProcessJava over gRPC

  Note over T,J: 5. Policy removal
  T->>J: POLICY_REMOVE (policy id)
  Note right of J: un-instrument classes, free hooks
  J->>T: ACK
```

Three channels are involved:

1. **HotSpot Attach protocol**: one-shot, Tetragon to JVM, makes the JVM
   `dlopen` the agent.
2. **Control channel**: `AF_UNIX`/`SOCK_SEQPACKET` socket, opened by the agent
   to Tetragon. Carries handshake and policy commands.
3. **Data ring**: memfd shared memory created by Tetragon, mapped by both
   sides. Carries method definitions and entry events from the JVM.

## 2. Policy load

`policyHandler.PolicyHandler` (`java_linux.go`) is registered at init for the
`java` spec section.

1. Rejects policy filtering (`filterID != NoFilterID`).
2. Validates `targets.executables` (absolute, clean, no NUL) and
   `targets.processArgsContains` (non-empty, no NUL). A policy without hooks
   must name at least one executable.
3. If hooks are present, resolves the native agent library, in order:
   `--java-agent-path`, `<cwd>/pkg/javaattach/agent/tetragon-jvmti.so`,
   `/usr/lib/tetragon/tetragon-jvmti.so`.
4. Builds a `javaagent.Policy`:
   * `ID` = FNV-1a hash of the policy long name (never 0),
   * one `Hook` per `spec.hooks[i]` (`HookID = i`, kind class or prefix,
     `.` replaced by `/`),
   * `Meta[i]` = message and tags, kept on the Tetragon side only.
5. Returns a `javaSensor`.

`javaSensor.Load` then starts the shared `javaagent.Server` (once per
process, `ensureServer`), calls `Server.SetPolicy`, runs an initial `scan()`
and starts a watcher goroutine that scans every second.

## 3. Discovering JVMs and authorizing them

`scan()` walks `/proc`:

* PID parsed from the directory name (`pid > 1`),
* `exe` must be in `executables`; if none are configured, `/proc/<pid>/maps`
  must contain `libjvm.so`,
* `/proc/<pid>/cmdline` must contain all `processArgsContains` tokens,
* process identity is `(pid, startTicks)`, with `startTicks` = field 22 of
  `/proc/<pid>/stat`. This defeats PID reuse.

For each candidate not yet active (and not tried in the last 5 s):

1. `Server.AllowProcess(policyID, pid, startTicks)` puts the identity on the
   allow-list. This happens **before** attaching, because the agent's
   connection is authenticated against it.
2. A global refcount `attachedVMs[(pid,startTicks)]` is kept across policies.
   If the JVM already has the agent, only the count is incremented and the
   new policy is delivered over the existing session. Otherwise `attach()` is
   called.
3. Processes that disappeared (or whose start time changed) are revoked
   (`RevokeProcess`) and the refcount is decremented.

## 4. Injecting the agent

`javaSensor.attach` + `javaattach.LoadNativeAgent`:

```mermaid
sequenceDiagram
  participant S as javaSensor.attach
  participant FS as /proc/PID/root/tmp
  participant A as LoadNativeAgent
  participant JVM as HotSpot (target JVM)

  S->>S: readProcessIdentity, verify startTicks
  S->>FS: write .tetragon-jvmti-PID-TICKS.so (0555)
  S->>A: LoadNativeAgent(pid, /tmp/.tetragon-jvmti-..so, socketPath)
  A->>A: NSpid from /proc/PID/status -> nspid
  A->>JVM: dial /proc/PID/root/tmp/.java_pid<nspid>
  alt listener not running
    A->>FS: create /tmp/.attach_pid<nspid> (chown to JVM uid/gid)
    A->>JVM: kill(pid, SIGQUIT)
    JVM->>FS: create .java_pid<nspid> socket
    A->>JVM: retry dial (100 ms, up to 10 s)
  end
  A->>JVM: "1\0load\0<lib>\0true\0<socketPath>\0" then shutdown(write)
  JVM->>JVM: dlopen(lib), Agent_OnAttach(vm, socketPath)
  JVM-->>A: "<status>\n<message>"
  S->>FS: remove the .so copy (defer)
```

The library is copied into the target's own `/tmp` (through
`/proc/<pid>/root`) so that it is visible inside the JVM's mount namespace,
which makes containers work. The trigger file and the `.so` copy are removed
afterwards.

### Attach request format

Text protocol on the HotSpot Unix socket. Each field is NUL-terminated:

```
"1\0"            protocol version
"load\0"         command
"<lib path>\0"   absolute path as seen inside the JVM mount ns
"true\0"         "absolute path" flag
"<options>\0"    passed to Agent_OnAttach = Tetragon control socket path
```

Each argument is limited to 1024 bytes (HotSpot limit). Reply:

```
"<status>\n<message>"
```

`status != 0` is an error. A message containing `return code: -1` is
treated as the agent having failed.

## 5. Control channel

The agent calls `connect()` on the Tetragon socket
(`/var/run/tetragon/java.sock` by default, `--java-agent-socket-path`),
type `SOCK_SEQPACKET`; one `send()` is one message (max 64 KiB).

### 5.1 Message header (8 bytes, every message)

```
 0        2        4                8
 +--------+--------+----------------+
 | type   | flags  |      seq       |
 |  u16   |  u16   |      u32       |
 +--------+--------+----------------+
```

`flags` is always 0. `seq` is 0 for HELLO; for commands it is a per-session
counter starting at 1, echoed in the ACK.

### 5.2 Message types

| type | name | direction | payload |
|---:|---|---|---|
| 1 | HELLO | JVM -> Tetragon | 5.3 |
| 2 | RING | Tetragon -> JVM | 5.4 (+ fd via `SCM_RIGHTS`) |
| 3 | HOOK_ADD | Tetragon -> JVM | 5.5 |
| 4 | POLICY_COMMIT | Tetragon -> JVM | `u32 policy_id` |
| 5 | POLICY_REMOVE | Tetragon -> JVM | `u32 policy_id` |
| 6 | ACK | JVM -> Tetragon | 5.6 |

### 5.3 HELLO

```
 payload
 0        4        6
 +--------+--------+------------------+
 | proto  | vm_len | vm_version       |
 |  u32   |  u16   | vm_len bytes     |
 +--------+--------+------------------+
```

`proto` must equal `1` (`ProtoVersion`). `vm_version` is `java.vm.version`,
truncated to 255 bytes, informational.

### 5.4 RING

```
 payload
 0
 +----------------+
 |   data_size    |    u64, size of the ring data area (4 MiB)
 +----------------+
 ancillary data: SCM_RIGHTS with 1 fd (the ring memfd)
```

### 5.5 HOOK_ADD

```
 payload
 0         4         8     9     10        12
 +---------+---------+-----+-----+---------+------------------------------+
 |policy_id| hook_id |kind | rsv |nr_method| str class_name               |
 |  u32    |  u32    | u8  | u8  |  u16    |                              |
 +---------+---------+-----+-----+---------+------------------------------+
 followed by nr_methods times:  str name | str descriptor
```

* `kind`: `1` = exact class, `2` = class prefix (`class_name` is the prefix).
* `nr_methods = 0` means all methods of the matched classes.
* The payload must be consumed exactly, otherwise the agent returns an error
  ACK.
* The agent ignores a `(policy_id, hook_id)` it already has.

### 5.6 ACK

```
 payload
 0        4        8        12       14
 +--------+--------+--------+--------+---------------+
 | seq    | status |classes |err_len | err message   |
 |  u32   |  i32   |  u32   |  u16   | err_len bytes |
 +--------+--------+--------+--------+---------------+
```

`status = 0` is success. `err_len <= 250`. `classes` is currently always 0.
Tetragon waits up to 10 s for each ACK and checks `type == ACK` and that the
`seq` matches. Commands are strictly one at a time per session.

### 5.7 Session setup and policy delivery

```mermaid
sequenceDiagram
  participant S as Tetragon Server
  participant J as JVM agent (Agent_OnAttach)
  participant C as agent control thread

  J->>S: connect(java.sock)
  S->>S: SO_PEERCRED -> pid, read startTicks
  S->>S: (pid,startTicks) in AllowProcess list? else close
  J->>S: HELLO(proto=1, vm_version)
  S->>S: version check, NewRing(4 MiB memfd)
  S->>J: RING(data_size) + fd (SCM_RIGHTS)
  J->>J: mmap ring, validate magic/version/size
  J->>J: AddCapabilities, define io/tetragon/TetragonHook,<br/>enable ClassFileLoadHook, start control thread
  loop for each stored policy
    loop for each hook
      S->>C: HOOK_ADD(seq n)
      C-->>S: ACK(seq n, status)
    end
    S->>C: POLICY_COMMIT(policy_id)
    C->>C: mark hooks committed, RetransformClasses(matching loaded classes)
    C-->>S: ACK
  end
  S->>S: session.drain() loop on the ring
```

Later `SetPolicy` calls (new policies while JVMs are attached) run the same
HOOK_ADD / COMMIT sequence on every live session. Unloading a policy sends
POLICY_REMOVE:

```mermaid
sequenceDiagram
  participant S as Tetragon (RemovePolicy)
  participant C as agent control thread
  S->>C: POLICY_REMOVE(policy_id)
  C->>C: uncommit hooks
  C->>C: RetransformClasses(classes that were instrumented)
  C->>C: free hooks and method matches
  C-->>S: ACK
```

The agent cannot be unloaded from a JVM (JVMTI limitation); after the last
policy is removed it stays loaded and idle. If the control connection
breaks, the agent cleans up its session state.

## 6. Instrumentation inside the JVM

* The agent defines the bootstrap class `io/tetragon/TetragonHook` with a
  native method `enter(J)V`, bound to the C function `hook_enter`.
* `ClassFileLoadHook` fires for every class load and retransform. Classes in
  `java/`, `jdk/`, `sun/` and `io/tetragon/` are never touched.
* `transform_class` rewrites matching classes: for every method matching a
  committed hook (class exact/prefix, method name + descriptor if given), a
  call to `TetragonHook.enter(key)` is inserted at method entry (constant
  pool, StackMapTable and annotations are adjusted; bytecode it cannot
  rewrite safely is rejected).
* `key` is a JVM-local `u64` identifying one matched
  (policy, hook, class, method, descriptor) tuple (`method_match`).
* On POLICY_COMMIT the already-loaded matching classes are retransformed, so
  methods are hooked even for classes loaded before the attach.

## 7. Data ring

Created by Tetragon (`NewRing`): memfd `tetragon-java-ring`, size
`4096 + data_size`, `data_size` a power of two (4 MiB). Single producer
(agent), single consumer (Tetragon).

### 7.1 Ring header (4096 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | u32 | magic `0x4a56544d` |
| 4 | u32 | version (1) |
| 8 | u64 | data_size |
| 64 | u64 | producer_pos (monotonic bytes, own cache line) |
| 128 | u64 | consumer_pos (monotonic bytes, own cache line) |
| 192 | u64 | dropped (METHOD_ENTRY records dropped, ring full) |
| 200 | u64 | dropped_defs (METHOD_DEF records dropped) |
| 208 | u32 | notify (futex word) |
| 212 | u32 | consumer_waiting |

The data area starts at offset 4096. A position maps to the offset
`pos & (data_size - 1)`.

### 7.2 Record framing

```
 0        4        8
 +--------+--------+----------------------------+
 | len    | type   | payload (zero padded)      |
 |  u32   |  u32   |                            |
 +--------+--------+----------------------------+
```

* `len` is the total record length including this 8-byte header, a multiple
  of 8.
* The producer writes type and payload first, then stores `len` with release
  semantics, and then advances `producer_pos`. A reader never sees a
  partial record.
* If a record does not fit before the end of the data area, a `PAD` record
  covering the tail is written and the record starts at offset 0.
* If the ring is full the record is dropped and the matching `dropped*`
  counter is incremented. The producer never blocks.

| type | name |
|---:|---|
| 1 | PAD (skip `len` bytes) |
| 2 | METHOD_DEF |
| 3 | METHOD_ENTRY |

### 7.3 METHOD_DEF

Emitted once per method, before its first entry event.

```
 0         8          12        16      18      20      22     24
 +---------+----------+---------+-------+-------+-------+------+----------------------+
 |  key    |policy_id | hook_id |cls_len|nam_len|dsc_len| rsv  | class|name|descriptor|
 |  u64    |   u32    |  u32    |  u16  |  u16  |  u16  | u16  | (concatenated, +pad) |
 +---------+----------+---------+-------+-------+-------+------+----------------------+
```

Tetragon verifies that the lengths add up and that all padding bytes are
zero; it stores the definition in a per-session `key -> definition` map.

### 7.4 METHOD_ENTRY

```
 0         8           16        20       24
 +---------+-----------+---------+--------+
 |  key    |  ktime    |  tid    |  rsv   |
 |  u64    |  u64      |  u32    |  u32   |
 +---------+-----------+---------+--------+
```

* `ktime`: `CLOCK_MONOTONIC` in nanoseconds (same clock as the rest of
  Tetragon's `ktime`).
* `tid`: Linux thread id (`gettid`).
* An entry whose `key` has no stored definition is ignored (e.g. its
  METHOD_DEF was dropped).

### 7.5 Wakeup

```mermaid
sequenceDiagram
  participant P as agent (producer)
  participant R as ring
  participant C as Tetragon session.drain (consumer)
  C->>R: drain all records
  C->>R: consumer_waiting = 1
  C->>R: producer_pos == consumer_pos ? futex_wait(notify, 100 ms)
  P->>R: write record, producer_pos += len
  P->>R: if consumer_waiting: notify++, futex_wake(notify)
  C->>R: consumer_waiting = 0, drain again
```

The 100 ms timeout also lets Tetragon notice that the JVM died without
sending a wakeup (the session ends when the control connection is dead).

## 8. Runtime event flow

```mermaid
sequenceDiagram
  participant M as Java thread (hooked method)
  participant H as hook_enter (C)
  participant R as ring
  participant D as session.drain
  participant K as sink / observer
  participant G as gRPC

  M->>H: TetragonHook.enter(key)
  H->>H: ktime = CLOCK_MONOTONIC, tid = gettid
  H->>R: first time for key: METHOD_DEF
  H->>R: METHOD_ENTRY(key, ktime, tid)
  R->>D: records
  D->>D: methodDef: cache definition
  D->>D: methodEntry: look up def + policy, hook metadata
  D->>K: (pid, tid, ktime, methodID, class, method, desc, policyName, message, tags)
  K->>G: MsgJavaEvent -> GetEventsResponse{ProcessJava}
```

Fields Tetragon adds (they are not in the ring):

| Field | Source |
|---|---|
| `pid` | `SO_PEERCRED` of the control connection |
| policy name | policy looked up by `policy_id` |
| `message`, `tags` | `Policy.Meta[hook_id]` |
| `methodID` | `FNV-64a(class\0method\0descriptor\0)`, stable across JVMs |

`MsgJavaEvent.HandleMessage` converts the event to
`GetEventsResponse{ProcessJava}`; the process is resolved from the process
cache by pid and timestamp (`RetryInternal`/`Retry` when it is not known
yet).

## 9. Security and robustness notes

* **Authentication**: the control socket is world-writable (0666), so
  access is controlled by `SO_PEERCRED` + `(pid, startTicks)` matching an
  `AllowProcess` entry. Connections from anything else are closed before any
  data is read.
* **PID reuse**: every decision uses `(pid, startTicks)`, not the PID alone.
* **Message limits**: control packets are at most 64 KiB; `MSG_TRUNC` is
  rejected; all strings are length-checked; HOOK_ADD must be consumed
  exactly; ring records are validated (lengths, zero padding).
* **No blocking in the JVM**: a full ring drops events (counted in the ring
  header) instead of stalling application threads.
* **Policy ID collisions**: a different policy name with the same hashed ID
  is rejected by `SetPolicy`.
* **Retry**: failed attaches are retried at most every 5 s per PID.
* **Cleanup**: the temporary `.so` copy and the `.attach_pid` trigger file
  are removed after attach; the agent library itself stays loaded in the JVM
  until it exits.

## 10. Summary of a complete lifecycle

1. Policy applied: `PolicyHandler` validates it and `Load` registers it with
   the server.
2. `scan()` finds a matching JVM and calls `AllowProcess(pid, startTicks)`.
3. Tetragon copies the agent `.so` into the target's `/tmp` and asks HotSpot
   to load it via the Attach protocol.
4. The agent connects back, sends HELLO and receives the ring memfd.
5. Tetragon sends HOOK_ADD (per hook) and POLICY_COMMIT; the agent
   retransforms matching classes.
6. Hooked methods write METHOD_DEF / METHOD_ENTRY records into the ring.
7. Tetragon drains the ring, enriches the events and emits `ProcessJava`
   events through gRPC.
8. Policy removal sends POLICY_REMOVE; the agent un-instruments the classes.

## Source files

| Component | File |
|---|---|
| Policy handler, JVM discovery, attach orchestration | `pkg/sensors/java/java_linux.go` |
| HotSpot Attach client | `pkg/javaattach/attach_linux.go` |
| Control server, sessions, ring consumer | `pkg/javaagent/server_linux.go` |
| Wire formats, ring layout (Go) | `pkg/javaagent/proto.go`, `pkg/javaagent/ring_linux.go` |
| Native JVMTI agent (C) | `pkg/javaattach/agent/jvmti_agent.c` |
| Event to gRPC conversion | `pkg/grpc/tracing/java.go` |

