# Tetragon CEM support investigation

**Date:** 2026-09-22
**Status:** investigation complete
**Compared against:** Forest CEM v1 in `forest/docs/design/specs/event-model.md`
**Tetragon snapshot:** `2ea4b8357` (`2026-09-21`)

## Conclusion

Tetragon is a useful Linux observation source for Forest, but it is not a
complete CEM implementation. Its strongest native coverage is process
lifecycle telemetry, with additional raw kernel observations available through
policy-defined kprobes, tracepoints, uprobes, and LSM hooks.

The important boundary is between observing a kernel action and producing a
CEM event. CEM events carry normalized identity, provenance, semantic meaning,
coverage state, and delivery guarantees. Tetragon currently provides the
observation primitives, not the complete normalization and event-processing
contract.

No CEM event is contract-complete as emitted by Tetragon because the CEM
envelope itself requires fields that Tetragon does not expose, including
deterministic `event.id`, `event.received`, authenticated `source.id`, and
`machine.boot-id` (Forest CEM §1, envelope).
An adapter can add some of these fields, but it cannot recover source-native
sequence information or semantic context that was never captured.

## What Tetragon already provides

Tetragon describes itself as an eBPF-based security-observability and runtime-
enforcement component. Its default process lifecycle stream includes
`process_exec` and `process_exit`; its generic tracing surface includes
`process_kprobe`, `process_tracepoint`, and `process_uprobe` events. See the
Tetragon README and API definitions:

- `README.md`
- `api/v1/tetragon/tetragon.proto`, especially `Process`, `ProcessExec`, and
  `ProcessExit`
- `api/v1/tetragon/events.proto`, especially `GetEventsResponse`
- `pkg/process/process_id_linux.go`, which derives `exec_id` from node name,
  kernel time, and PID

The process records include useful CEM inputs: executable path, command line,
current working directory, PID, process start time, parent identity, effective
UID, optional username metadata, credentials, capabilities, namespaces, and
Kubernetes/container metadata. Tetragon also has a process cache and retry path
for enriching generic events with process information.

The generic tracing surface can observe more actions when an appropriate
TracingPolicy is installed. Existing examples cover TCP connection and accept
observation, listen detection, DNS-related hooks, file access, and library
loading. These examples demonstrate capability, not universal coverage: the
events depend on selected hooks, kernel symbols, kernel features, and policy
configuration.

## CEM support matrix

The ratings below distinguish raw observability from a CEM-compliant semantic
event.

| CEM area | Current Tetragon support | Main missing pieces |
|---|---|---|
| `process.start` | **High after adaptation** | Guaranteed image SHA-256, signing certificate, image metadata, artifact provenance, operation/service/session/task joins |
| `process.end` | **High after adaptation** | CEM envelope and guaranteed start/end accounting |
| Process identity | **Good basis** | Explicit stable `machine.id` and `machine.boot-id`; CEM uses `(machine, boot, PID, start-time)` rather than PID alone |
| `privilege.change` | **Partial** | Authorization request/result, initiating identity, target identity, policy/action identity, and elevation operation join |
| `network.connect` | **Partial** | First-class normalized event, DNS/TLS enrichment, certificates, bytes, service/session context, provenance |
| `network.accept` | **Partial** | CEM both-ends correlation and derived remote initiator; NAT/proxy handling |
| `network.listen` | **Partial** | Stable normalized listener stream and service ownership joins |
| `dns.query` | **Partial** | Canonical query/response event, process attribution rules, and coverage reporting |
| `file.write` / `file.delete` | **Partial** | Stable write/delete semantics, file identity, operation/provenance context, deletion kind, and explicit loss/degradation |
| `file.exec-write` | **Low to partial** | Executable-content classification, reliable file SHA-256, script classification, artifact provenance, and operation joins |
| `module.load` | **Partial** | Tetragon's loader event has path and build ID, but CEM requires stronger module identity, SHA-256, signing certificate, and context joins |
| `module.invoke` | **Partial with custom probes** | Normalized module identity, entrypoint semantics, provenance, and service/session context |
| `process.sensitive-handle` | **Possible with custom probes** | Sensitive-target classification, target process reference, access intent, and source-module attribution |
| `script.execute` | **Weak** | Script identity, source kind, hash/signature, phase, provenance, and distinct execution semantics rather than interpreter start |
| `registry.*` | **Absent on Linux** | Windows registry sensor and normalized registry contract |
| `persistence.register` | **Weak raw evidence only** | Mechanism-level registration semantics, target/scope, API-only cases, and service/task joins |
| `certificate-store.change` | **Absent** | Platform certificate-store telemetry |
| `transfer.job` / `package.install` | **Absent as semantic events** | Operation identity, initiator, source/destination, package/job identity, and resulting artifacts |
| `service.session` / `service.operation` / `service.policy` | **Absent** | Service registry, authenticated principal, resource/operation identity, effective policy, and result semantics |
| `container.operation` | **Limited context only** | Container-engine API operation, initiator, image/config identity, peer/session, and resulting process/artifact joins |
| `service.activation` / `task.execute` | **Absent as semantic events** | launchd and scheduler registration/execution records, definitions, triggers, and action identity |
| `automation.invoke` / `privacy.access` / `code.assessment` | **Absent** | macOS interapplication automation, TCC, and Gatekeeper sources |

Therefore:

- Tetragon is a strong candidate for the CEM's Linux process-lifecycle source.
- It is a useful partial source for Linux network, file, module, credential, and
  kernel-security observations.
- It is not a source for most platform-semantic events without substantial new
  sensors and userspace correlation.
- Generic tracing policies must not be treated as proof of CEM coverage. The
  coverage map must record which policies, hooks, and kernel capabilities are
  actually active.

## Missing CEM pipeline behavior

The gaps are not limited to fields.

### Envelope and source identity

The CEM requires deterministic event identity, ingestion time, authenticated
sensor identity, stable machine identity, boot identity, explicit user
identity, and degradation states. Tetragon's event response has an event type
and observation timestamp, but no CEM event ID or received timestamp. Its
`exec_id` is a process identity, not an event identity.

An adapter can assign `source.id`, `source.kind`, and `event.received`, and can
obtain a boot ID from the host. It must not pretend that a receiver timestamp
or a process ID is equivalent to the source sequence/offset required for robust
redelivery identity.

### Process and cross-event joins

Tetragon performs local process-cache enrichment and has retry behavior for
events whose process metadata is not immediately available. The CEM requires a
separate, explicit process join contract: hold action events for a bounded
interval, release them in event-time order, mark unresolved events, and process
late events without silently dropping them (Forest CEM §3.0, process join).

The CEM also requires both-ends network correlation to populate an accepting
event's remote initiator. Tetragon does not provide that cross-sensor,
cross-machine correlation (Forest CEM §3.1, both-ends join).

### Exactly-once effects

Tetragon supports event aggregation and reports event-loss-related operational
information, but that is not the CEM's exactly-once effect guarantee. Forest
still needs event-ID deduplication plus open-state effect coalescing for
questions, violations, alerts, and counters (Forest CEM §4, exactly-once effects).

This logic belongs in the Forest ingestion/evaluation pipeline rather than in
the kernel sensor. Tetragon should preserve enough source identity and loss
information for Forest to make the result correct and auditable.

## Recommended architecture

Keep Tetragon as a sensor and add a Forest-side Tetragon normalizer.

```text
Tetragon process/generic events
        │
        ▼
Tetragon source adapter
  - source authentication
  - event ID policy
  - machine/boot identity
  - received time and loss metadata
  - CEM field mapping
        │
        ▼
Forest CEM pipeline
  - semantic normalization
  - process/service/task/operation joins
  - both-ends correlation
  - coverage and degradation
  - deduplication and effect coalescing
```

This preserves Tetragon's strength—low-level Linux observation—without making
the sensor responsible for customer-scoped knowledge, cross-source joins, or
Forest's downstream effect lifecycle.

Tetragon should be extended with new first-class event types only where a
kernel-native observation is stable, broadly useful, and impossible to express
faithfully through the current generic event surface. Platform-semantic events
such as Windows registry/service/task activity and macOS launchd/TCC/Gatekeeper
activity should be implemented by platform-specific collectors or complementary
sources, not forced into Linux eBPF policy abstractions.

## Effort estimate

These estimates assume production quality, test coverage, loss/degradation
reporting, and compatibility work—not only a schema conversion.

| Deliverable | Estimate | Result |
|---|---:|---|
| CEM-shaped Linux adapter | 4–8 weeks, 1–2 engineers | Process lifecycle plus mapped raw network/file/module events, with explicit gaps |
| CEM-complete Linux sensor path | 6–12 months, 3–4 engineers | Strong process/network/file coverage, identity, joins, loss reporting, and delivery semantics |
| Full cross-platform CEM support | 12–18+ months, 5–7 engineers | Linux, Windows, and macOS semantic sources plus verification across supported OS versions |
| Production hardening | Additional 3–6 months | Kernel/OS matrix, upgrade compatibility, performance, security review, and field validation |

A full fork is approximately **40–70 engineer-months**, with ongoing cost for
rebasing Tetragon changes, kernel compatibility, generated APIs, BPF behavior,
and third-party source updates. The estimate is materially lower if Forest
accepts Tetragon as one Linux source and keeps CEM joins and effect semantics
outside the fork.

## License and distribution notes

The Tetragon repository is primarily Apache-2.0 licensed. The `bpf/` directory
has its own dual GPL-2.0-only/BSD-2-Clause notice, and bundled `libbpf` headers
include LGPL-2.1-or-BSD-2-Clause notices. A fork can be distributed, but it
must preserve applicable license, copyright, attribution, and modification
notices and must not imply Cilium/Tetragon trademark endorsement.

Forest did not have a top-level license or notice file at the time of this
investigation. Before distributing a combined product, Forest needs an explicit
license decision and a dependency/license inventory. The investigation also
identified an Elastic License 2.0 note for a possible development telemetry
source in `docs/design/open-issues.md`; that source must remain separated from
any redistributable or embedded product path unless its terms are reviewed.

This section is an engineering compliance summary, not legal advice.

## Source evidence

Forest sources:

- `docs/design/specs/event-model.md`
- `docs/design/04-requirements.md`
- `docs/design/open-issues.md`

Tetragon sources at `2ea4b8357`:

- `LICENSE`
- `bpf/COPYING`
- `bpf/LICENSE.GPL-2.0`
- `bpf/LICENSE.BSD-2-Clause`
- `README.md`
- `api/v1/tetragon/events.proto`
- `api/v1/tetragon/tetragon.proto`
- `pkg/process/process_id_linux.go`
- `pkg/grpc/tracing/tracing.go`
- `examples/tracingpolicy/tcp-connect.yaml`
- `examples/tracingpolicy/tcp-accept.yaml`
- `examples/tracingpolicy/openat_write.yaml`
- `examples/tracingpolicy/loader.yaml`
