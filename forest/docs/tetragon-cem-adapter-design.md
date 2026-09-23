# Forest Tetragon adapter design

**Status:** Design ready for review
**Date:** 2026-09-22
**Forest CEM reference:** [CEM v1 at revision `ed4c870eff73`](https://github.com/kvjudson/forest/blob/ed4c870eff73677e59bf5a29adfc9c4a7afd5e15/docs/design/specs/event-model.md)
**Related investigation:** [`tetragon-cem-support.md`](tetragon-cem-support.md)

## Decision

Build a Forest-side Tetragon source adapter. Keep Tetragon responsible for
Linux kernel observation and process metadata; keep CEM normalization, joins,
coverage, degradation, deduplication, and downstream effect semantics in
Forest.

Do not fork Tetragon for CEM-specific behavior in the first phase. Make the
Tetragon extension boundary narrow and upstreamable: add or request Tetragon
metadata only when the adapter cannot obtain a required source fact, such as a
source-native action timestamp or a replay-safe source sequence.

## Goals

- Produce contract-compliant CEM `process.start` and `process.end` events from
  Tetragon process lifecycle records.
- Map selected network, file, and module observations when the source provides
  the required CEM fields and action time.
- Preserve the distinction between action time and observation/ingestion time.
- Assign authenticated source, machine, boot, user, and process identity.
- Expose missing fields, event loss, unsupported policies, and unresolved joins
  through explicit coverage/degradation state.
- Define a stable handoff into the Forest CEM pipeline without moving Forest's
  cross-source semantics into the kernel sensor.
- Leave every unsupported capability in the TODO register below with an owner
  boundary, trigger, and completion condition.

## Non-goals for the first phase

- Making Tetragon emit Forest CEM directly.
- Reimplementing Tetragon's eBPF instrumentation in a new sensor.
- Claiming generic kprobes, tracepoints, or uprobes are CEM events when their
  records do not contain an action timestamp.
- Implementing Windows or macOS event families.
- Implementing Forest process joins, both-ends network correlation, rule
  evaluation, or exactly-once effect coalescing inside the adapter.
- Inferring required identity or provenance fields from weak substitutes.

## Rejected approaches

### CEM-native Tetragon fork

This would reduce the distance between sensor output and the CEM schema, but it
would couple a Linux observation project to Forest-specific semantic and
customer-scoped behavior. It would also create a long-lived fork for joins,
coverage, effect semantics, and platform features that Tetragon cannot own.

Use a fork later only when a narrowly defined source capability cannot be
upstreamed and cannot be implemented safely in the adapter.

### New sensor modeled after Tetragon

This would duplicate eBPF hook selection, kernel-version compatibility,
buffering, process-cache behavior, and policy management. It is not justified
while Tetragon supplies the required Linux observations.

## Architecture

```text
Tetragon agent
  gRPC event stream + health/loss signals
        │ authenticated transport
        ▼
Tetragon source adapter
  1. receive and preserve source records
  2. assign source/machine/boot identity
  3. classify capabilities and degradation
  4. normalize supported records into CEM events
  5. quarantine records that cannot satisfy required fields
        │ normalized CEM events + coverage diagnostics
        ▼
Forest CEM ingestion pipeline
  process join, both-ends join, service/operation joins,
  event-id dedupe, effect coalescing, rules, questions,
  violations, alerts, counters, and customer state
```

The adapter should be a separate Forest-owned component or package. Its public
interface should accept a Tetragon event stream and return two typed outputs:

1. `NormalizedEvent` — a CEM event that satisfies the declared event contract
   with explicit expected-field degradation where applicable. Records missing
   required fields are not emitted as `NormalizedEvent` values.
2. `SourceDiagnostic` — authentication failures, malformed records, source
   loss, unsupported event mappings, quarantine decisions, policy coverage,
   timestamp problems, and join prerequisites.

The adapter must preserve the original Tetragon protobuf bytes and source
metadata alongside each normalized event or diagnostic. This supports audit,
replay, debugging, and later remapping when the CEM contract evolves.

## Input contract

The first implementation should consume Tetragon's versioned protobuf stream,
not scrape human-readable JSON. The relevant source records are:

- `GetEventsResponse.process_exec` for process starts;
- `GetEventsResponse.process_exit` for process ends;
- `GetEventsResponse.process_kprobe`, `process_tracepoint`, and
  `process_uprobe` for policy-defined observations;
- `GetEventsResponse.process_loader` for module-load evidence;
- `GetEventsResponse.process_lsm` where a configured LSM hook maps to a
  supported observation;
- `GetEventsResponse.time`, `node_name`, `cluster_name`, and `node_labels` as
  observation and source-context metadata, never as a substitute for an
  action timestamp.

The receiver must treat Tetragon event types, protobuf fields, policy names,
tags, and argument schemas as versioned input. Mapping logic must reject or
diagnose unknown schema variants rather than silently treating them as a
known semantic event.

## CEM mapping contract

### Envelope

| CEM field | First-phase source or policy | Rule |
|---|---|---|
| `event.type` | Mapping table keyed by Tetragon event type plus policy identity | Only declared mappings may produce CEM events. |
| `event.time` | `Process.process.start_time` for starts; `ProcessExit.time` for exits; source-native action timestamp for any future generic mapping | `GetEventsResponse.time` is observation time and must not be copied into `event.time` for generic records. |
| `event.received` | Adapter clock at successful receipt | Recorded independently of action time; used for skew and latency. |
| `event.id` | Deterministic hash of authenticated source identity, CEM type, canonical source payload, and source cursor/offset where available | Process lifecycle IDs may use the process-instance key when no cursor exists. Generic events without collision-safe identity are quarantined. |
| `source.id` | Authenticated Tetragon instance identity | Unauthenticated input is rejected before normalization. |
| `source.kind` | Fixed value such as `tetragon` plus adapter version metadata | Must not vary based on policy name. |
| `machine.id` | Forest host identity provider | The adapter does not derive stable identity from `node_name` alone. |
| `machine.boot-id` | Linux host boot ID | Required to disambiguate PID reuse. |
| `user.id` | Tetragon UID/AUID/process credentials where available | Missing identity is explicit degradation; it is never inferred from username text. |
| `process.ref` | `(machine.id, machine.boot-id, pid, process.start_time)` | PID alone is never used as process identity. |

### Supported first-phase events

| CEM event | Initial input | First-phase disposition |
|---|---|---|
| `process.start` | `process_exec` | Emit when executable path, process reference, parent reference, command line, cwd, and image hash policy are satisfied. Missing expected identity evidence is disclosed. |
| `process.end` | `process_exit` | Emit with the process reference and `ProcessExit.time`; pair/accounting is completed by the Forest pipeline. |
| `network.connect` | Explicit network TracingPolicy mapping | Emit only when the policy supplies normalized addresses, ports, protocol, process reference, and action time. Otherwise retain as raw/quarantined evidence. |
| `network.accept` | Explicit network TracingPolicy mapping | Emit only with the accepting endpoint's local truth; `initiator` is always left for the both-ends join. |
| `network.listen` | Explicit network TracingPolicy mapping | Emit only when listener address, port, protocol, process reference, and action time are available. |
| `dns.query` | Explicit DNS policy mapping | Emit only when query name and action time are available; response data remains expected/degraded when absent. |
| `file.write` / `file.delete` | Explicit file-related policy mapping | Emit the observed process and path; hash, deletion kind, provenance, and operation context are optional/expected according to source coverage. |
| `file.exec-write` | File policy plus executable-content classifier | Emit only after content/path classification and required file hash are available. Otherwise keep the observation as a diagnostic/raw record. |
| `module.load` | `process_loader` plus file identity enrichment | Emit when process reference, module path, module hash policy, and action-time policy are satisfied. Build ID alone is not a SHA-256. |

All mappings must be configuration- and version-gated. A policy being enabled
is evidence of collection intent, not proof that the resulting stream covers
the complete CEM event type.

## Timestamp policy

The CEM requires `event.time` to represent when the action occurred. The
adapter must apply these rules:

1. Use `Process.start_time` for `process.start`.
2. Use `ProcessExit.time` for `process.end`.
3. Use a source-native action timestamp for generic events only after Tetragon
   exposes one or the selected policy carries one in a documented field.
4. Never map `GetEventsResponse.time` into CEM `event.time` merely because it
   is available; it is an observation timestamp.
5. If a required action timestamp is missing, do not emit a normal CEM event.
   Emit a `SourceDiagnostic` with `reason=missing-action-time`, retain the raw
   record for replay/audit, and mark the event family as degraded in coverage.

This makes timestamp incompleteness visible instead of corrupting event-time
ordering and process/network joins.

## Identity and redelivery policy

The adapter must establish the following before normalization:

- Transport authentication binds input to a configured Tetragon instance and
  produces `source.id`.
- Host identity provides stable `machine.id` and reads the current Linux boot
  ID for `machine.boot-id`.
- Process references use the CEM tuple, including process start time.
- Raw protobuf bytes are retained in deterministic form for hashing and audit.
- If Tetragon supplies a replay-safe cursor/offset, it participates in
  `event.id`; otherwise generic events do not claim collision-free identity.

The adapter's event-ID deduplication is an optimization. Forest's downstream
effect coalescing remains the correctness mechanism for questions, violations,
alerts, and other open effects.

## Failure and degradation behavior

| Condition | Adapter behavior | Coverage effect |
|---|---|---|
| Unauthenticated source | Reject before normalization; record security diagnostic | Source unavailable/untrusted |
| Malformed protobuf or unknown required variant | Reject record; retain bounded raw evidence and diagnostic | Affected event family degraded |
| Missing required CEM field | Quarantine from normal CEM output; emit diagnostic | Required field gap recorded |
| Missing expected field | Emit event with explicit absence/degradation metadata | Expected coverage reduced |
| Missing action time | Never substitute receipt/observation time; quarantine raw record | Event-time coverage gap |
| Tetragon reconnect | Reconnect with backoff; resume from cursor if supported; otherwise record replay boundary | Possible source-loss interval disclosed |
| Tetragon throttling or buffer loss | Convert health/rate-limit signals into source diagnostics | Loss interval and affected policies recorded |
| Backpressure from Forest | Bound adapter queues, preserve diagnostics, and fail visibly rather than silently drop | Delivery degradation recorded |
| Ambiguous process or network join | Pass event to Forest with unresolved/ambiguous reason | Join coverage reduced; event is not dropped |

The adapter must not invent `initiator`, `service.ref`, `operation.ref`,
provenance, certificates, or component identity from the host process or policy
name alone.

## Forest pipeline boundary

The adapter hands off normalized events and source diagnostics. The Forest
pipeline owns:

- the five-minute provisional process join and late-attribution behavior;
- both-ends connection correlation, including NAT/proxy boundaries;
- service, session, task, operation, container, and artifact joins;
- event-ID dedupe windows;
- open-effect coalescing and downstream exactly-once behavior;
- customer/rule evaluation and coverage-map presentation.

The adapter may attach source facts and join keys, but it must not make a
cross-source attribution decision that Forest cannot audit or revise.

## Tetragon extension boundary

Before modifying Tetragon, verify that the missing fact cannot be obtained
from the configured policy, host identity provider, or Forest enrichment.
Potential upstreamable Tetragon changes are limited to:

- source-native action timestamps on generic trace records;
- a replay-safe source cursor/sequence and explicit loss boundary;
- stable raw-payload or schema-version metadata needed for deterministic
  normalization;
- first-class observation types where a kernel-native action is stable and
  generic policy arguments cannot represent it faithfully.

Forest-specific event IDs, CEM joins, customer context, rule semantics, and
effect state must not be added to Tetragon.

## Phased delivery

### Phase 0 — contract and fixture baseline

- Freeze the Forest CEM revision and mapping table.
- Capture representative Tetragon protobuf fixtures for process start/end,
  network, file, loader, generic trace, malformed input, throttling, and
  reconnect cases.
- Define adapter configuration, source authentication, machine identity,
  coverage vocabulary, and raw-record retention limits.

### Phase 1 — process lifecycle adapter

- Implement authenticated stream reception and raw record preservation.
- Normalize `process.start` and `process.end` with correct action times.
- Add deterministic lifecycle IDs, process references, expected-field
  degradation, and source diagnostics.
- Validate handoff into the Forest process-join pipeline.

### Phase 2 — gated Linux observations

- Add policy-versioned mappings for network connect/accept/listen, DNS, file
  write/delete, executable writes, and module loads.
- Require action-time and required-field capability checks per mapping.
- Add coverage records that identify enabled policy, kernel hook, and observed
  loss state rather than claiming universal support.

### Phase 3 — replay, loss, and operational hardening

- Add cursor/resume behavior when the source supports it.
- Validate reconnect, throttling, backpressure, raw replay, and diagnostic
  retention.
- Measure latency, skew, unresolved process rate, quarantine rate, and event
  loss by source and event family.

### Phase 4 — targeted Tetragon extensions, only if justified

- Select extensions from the TODO register based on measured coverage gaps.
- Propose upstream-compatible changes with independent Tetragon tests.
- Keep Forest adapter compatibility for old and new Tetragon schema versions.

## TODO register

These are intentionally deferred. Each item has a concrete trigger and exit
condition; a future plan should promote only the items justified by evidence.

| ID | Deferred capability | Owner boundary | Trigger to promote | Done when |
|---|---|---|---|---|
| T-001 | Action timestamps for generic kprobe/tracepoint/uprobe records | Tetragon source contract | A required Linux event family cannot be emitted because observation time is the only timestamp | Tetragon exposes a documented source-native action timestamp, and fixtures prove it survives buffering, aggregation, and reconnects |
| T-002 | Replay-safe source cursor/sequence | Tetragon transport plus adapter | Duplicate or loss analysis shows payload-only IDs can collide or cannot identify a replay boundary | Tetragon stream exposes a monotonic per-source cursor or equivalent, and redelivery tests reproduce the same ID without conflating distinct identical payloads |
| T-003 | Complete Tetragon loss accounting | Tetragon health contract plus adapter diagnostics | Production diagnostics cannot identify the affected policy/time interval after throttle or ring-buffer loss | Loss counters/events identify interval, policy/event family, and resumability; adapter coverage tests verify no silent gap |
| T-004 | Strong process image hash and signing evidence | Tetragon, host cataloger, or Forest enrichment | Process rules require hashes/certificates not available from Tetragon or catalog enrichment | `process.start` fixtures cover hash, certificate, missing evidence, truncation, and degraded evaluation |
| T-005 | Executable-write classification and hashing | Adapter plus host file identity service | `file.exec-write` coverage is required for ransomware or dropper rules | Classifier handles ELF/script/path cases, hashes content under bounded cost, and emits explicit unknown/degraded results |
| T-006 | Module SHA-256 and certificate enrichment | Adapter plus host file identity service | `module.load` rules require identity stronger than path/build ID | Loader fixtures resolve module hash/cert or disclose absence without substituting build ID |
| T-007 | Network action timestamps and normalized socket records | Tetragon source contract plus adapter | Network CEM coverage is blocked by generic policy records lacking action time/normalized endpoints | Connect/accept/listen fixtures contain source action time, five-tuple, protocol, and loss semantics across kernel versions in scope |
| T-008 | Process/service/session/task/operation joins | Forest CEM pipeline | Rules need attribution beyond process identity | Forest join interfaces consume adapter keys and produce auditable resolved, unresolved, late, and ambiguous states |
| T-009 | Both-ends correlation and NAT/proxy handling | Forest CEM pipeline plus network context source | Both-ends rules are enabled for deployments with translated or proxied traffic | Forest correlation tests cover clean mirrored tuples, NAT gaps, ambiguity, skew, and the five-second provisional window |
| T-010 | Exactly-once effects | Forest effect pipeline | Adapter integration reaches rule evaluation in production | Forest effect tests prove event redelivery cannot create duplicate open questions, violations, or alerts |
| T-011 | Container-engine semantic events | Complementary container source or Tetragon extension | Process context is insufficient for container lifecycle rules | A complementary container source or Tetragon extension emits authenticated operation, initiator, image/config, and resulting-process joins |
| T-012 | Linux persistence, package, transfer, and service semantics | Dedicated Linux semantic sources | Product requirements select those CEM families | A dedicated source contract exists for each family; raw syscall evidence is not accepted as semantic coverage |
| T-013 | Windows registry/service/task/certificate-store events | Native Windows collectors | Forest supports Windows CEM deployments | Native Windows sensor mappings satisfy the corresponding CEM contracts and coverage tests |
| T-014 | macOS activation/task/automation/privacy/code-assessment events | Native macOS collectors | Forest supports macOS CEM deployments | Native macOS collectors satisfy launchd, scheduler, TCC, automation, and Gatekeeper contracts |
| T-015 | Long-term schema and upstream compatibility | Adapter and Tetragon release process | Tetragon or Forest changes break fixture mappings | Version negotiation, migration tests, and a supported compatibility matrix are published |
| T-016 | Production security and performance hardening | Adapter release engineering | Phase 3 measurements show deployment readiness | Kernel/OS matrix, throughput/latency budgets, resource limits, authentication review, and upgrade procedure pass release gates |

## Acceptance criteria for the first release

- Every emitted event has an authenticated `source.id`, stable machine and boot
  identity, a CEM event type, and a deterministic event ID appropriate to its
  source capability.
- `process.start` uses process start time and `process.end` uses the exit
  action time; no event maps observation time into required CEM action time.
- Events missing required fields are quarantined and visible in coverage
  diagnostics; they are not silently downgraded into misleading CEM events.
- Process lifecycle fixtures pass for normal ordering, out-of-order delivery,
  PID reuse, reconnect, duplicate delivery, malformed records, and missing
  optional metadata.
- Gated network/file/module mappings cannot activate without the policy and
  source capability checks required by their mapping.
- The Forest pipeline receives enough process references and source diagnostics
  to implement its documented joins and exactly-once effect semantics.
- The TODO register remains current, and no deferred capability is described as
  supported merely because a generic Tetragon probe can observe related kernel
  activity.

## Testing strategy

- **Golden fixtures:** deterministic protobuf input and expected CEM/diagnostic
  output for each mapping.
- **Property tests:** event IDs are stable under redelivery; distinct source
  cursors do not collide; process references include boot and start time.
- **Failure tests:** authentication failure, malformed input, missing action
  time, missing required fields, throttling, reconnect, loss, backpressure,
  and unknown policy versions.
- **Contract tests:** compare emitted fields and required/degraded states with
  the pinned Forest CEM revision.
- **Integration tests:** verify adapter-to-pipeline handoff for process joins,
  late attribution, unresolved events, and diagnostic coverage.
- **Operational tests:** measure event latency, clock skew, queue growth,
  quarantine volume, loss visibility, and CPU/memory cost under representative
  policy sets.

## Security and licensing

The adapter must authenticate Tetragon before normalization, protect raw
records and diagnostics as telemetry data, and avoid treating policy names or
host-binary identity as authorization. Deployment must preserve Tetragon's
Apache-2.0, BPF GPL-2.0-only/BSD-2-Clause, and bundled libbpf
LGPL-2.1-or-BSD-2-Clause notices. Forest-side licensing and any combined
distribution decision remains a separate release gate.
