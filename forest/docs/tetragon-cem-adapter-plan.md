# Forest Tetragon adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Forest-owned Python adapter that converts authenticated,
versioned Tetragon protobuf events into contract-compliant Forest CEM events
and explicit source diagnostics, beginning with Linux process lifecycle and
capability-gated network, file, and module observations.

**Architecture:** The adapter lives in Forest under `sensor/tetragon/` and
consumes Tetragon's `FineGuidanceSensors.GetEvents` stream. It preserves raw
protobuf records, adds source/machine/boot identity, normalizes only mappings
whose required fields and action time are present, and emits diagnostics for
quarantined or degraded records. Forest's existing/future pipeline remains
responsible for process joins, both-ends correlation, semantic operation
joins, rule evaluation, deduplication, and exactly-once effects.

**Tech Stack:** Python 3.12+, `unittest`, `protobuf`/`grpcio` generated from
Tetragon snapshot `2ea4b8357`, dataclasses, typed protocols, deterministic
protobuf serialization, and JSON-compatible CEM mappings.

**Spec:** `forest/docs/tetragon-cem-adapter-design.md`

## Global Constraints

- The implementation is Forest-owned; do not add Forest-specific CEM joins,
  customer context, rule semantics, or effect state to Tetragon.
- Consume Tetragon's versioned protobuf stream; do not scrape human-readable
  JSON as the production input boundary.
- Use `Process.start_time` for `process.start` and `ProcessExit.time` for
  `process.end`.
- Never map `GetEventsResponse.time` into required CEM `event.time` for a
  generic record; quarantine records that lack action time.
- Required-field failures are quarantined with `SourceDiagnostic`; they are
  not emitted as misleading normal CEM events.
- Preserve the original deterministic protobuf bytes and source metadata for
  every normalized event or diagnostic.
- A policy being enabled proves collection intent only; it does not prove
  complete CEM coverage.
- Do not modify Tetragon until a deferred item reaches its documented trigger
  and the adapter cannot obtain the fact from host identity or Forest
  enrichment.
- Use TDD for every handwritten production behavior: RED failing test, verify
  the expected failure, GREEN minimal implementation, verify the focused and
  full suites, then refactor while green.
- Generated protobuf/grpc files are the only implementation exception; test
  their imports, serialization, and decoding before handwritten adapter code.

## Review Focus

- **Missing action time:** generic trace observations must be quarantined, not
  assigned receipt time; test in `test_generic_normalizer.py`.
- **Redelivery and identical payloads:** IDs must be stable for the same source
  cursor and must not conflate distinct cursors; test in `test_identity.py`.
- **PID reuse:** process references must include machine, boot, PID, and start
  time; test in `test_identity.py` and `test_process_normalizer.py`.
- **Untrusted or malformed input:** authentication and decode failures must
  stop normalization and produce bounded diagnostics; test in
  `test_receiver.py` and `test_decoder.py`.
- **Loss, reconnect, and backpressure:** source gaps must be visible and never
  silently dropped; test in `test_receiver.py` and `test_coverage.py`.

---

## File map

Implementation occurs in `/home/kylejudson/Dev/forest`; this plan is stored in
the Tetragon repository because that is the requested documentation location.

**Create in Forest:**

- `sensor/tetragon/__init__.py` — public adapter exports and version.
- `sensor/tetragon/models.py` — raw records, source context, adapter results,
  diagnostics, and immutable configuration types.
- `sensor/tetragon/proto/` — generated Python protobuf/grpc bindings and a
  manifest recording Tetragon commit `2ea4b8357`.
- `sensor/tetragon/decoder.py` — deterministic protobuf decoding and raw-byte
  preservation.
- `sensor/tetragon/identity.py` — source, machine, boot, process-reference,
  canonical-payload, and event-ID functions.
- `sensor/tetragon/coverage.py` — capability, policy, loss, and degradation
  records.
- `sensor/tetragon/policies.py` — versioned mapping declarations for enabled
  Tetragon policies and CEM event families.
- `sensor/tetragon/normalizer.py` — process lifecycle and gated event mapping.
- `sensor/tetragon/receiver.py` — authenticated stream transport, reconnect,
  cursor handling, and bounded delivery.
- `sensor/tetragon/runner.py` — adapter orchestration and output iteration.
- `sensor/tetragon/README.md` — configuration, supported mappings, and known
  gaps.
- `sensor/requirements.txt` — runtime protobuf/grpc dependencies.
- `sensor/requirements-dev.txt` — code-generation and test dependencies.
- `sensor/tests/__init__.py` — test package marker.
- `sensor/tests/tetragon_fixtures.py` — deterministic protobuf builders and
  source-context fixtures; test-only code.
- `sensor/tests/test_decoder.py`
- `sensor/tests/test_identity.py`
- `sensor/tests/test_coverage.py`
- `sensor/tests/test_process_normalizer.py`
- `sensor/tests/test_generic_normalizer.py`
- `sensor/tests/test_policy_mappings.py`
- `sensor/tests/test_network_mappings.py`
- `sensor/tests/test_file_mappings.py`
- `sensor/tests/test_module_mappings.py`
- `sensor/tests/test_receiver.py`
- `sensor/tests/test_runner.py`
- `sensor/tests/test_tetragon_contract.py`
- `sensor/tests/test_tetragon_reconnect.py`

**Modify in Forest:**

- `sensor/README.md` — replace the scaffolding-only statement with the
  production sensor boundary and link to the Tetragon adapter documentation.
- `validation_harness/events.py` only if the adapter's event representation is
  promoted into a shared CEM model; otherwise keep the existing harness
  compatibility boundary unchanged.

## Interfaces fixed by this plan

The following interfaces are the handoff between tasks:

```python
@dataclass(frozen=True)
class SourceContext:
    source_id: str
    source_kind: str
    machine_id: str
    boot_id: str

@dataclass(frozen=True)
class RawRecord:
    response: GetEventsResponse
    payload: bytes
    context: SourceContext
    received: datetime
    cursor: str | None

@dataclass(frozen=True)
class SourceDiagnostic:
    code: str
    severity: str
    event_family: str | None
    details: dict[str, str]
    payload_sha256: str | None

@dataclass(frozen=True)
class AdapterResult:
    event: dict[str, object] | None
    diagnostic: SourceDiagnostic | None

class TetragonNormalizer(Protocol):
    def normalize(self, record: RawRecord) -> AdapterResult: ...
```

`event` uses the existing Forest JSON-compatible event shape: top-level `id`,
`type`, `subject`, `action`, and `fields`. The adapter must populate the CEM
envelope fields inside `fields` consistently with the existing validation
harness.

## Task 1: Establish generated Tetragon input and fixture infrastructure

**Files:**

- Create: `sensor/requirements.txt`
- Create: `sensor/requirements-dev.txt`
- Create: `sensor/tetragon/__init__.py`
- Create: `sensor/tetragon/proto/__init__.py`
- Create: `sensor/tetragon/proto/manifest.json`
- Create: generated `sensor/tetragon/proto/tetragon/{bpf,capabilities,events,sensors,tetragon}_pb2.py`
- Create: generated `sensor/tetragon/proto/tetragon/sensors_pb2_grpc.py`
- Create: `sensor/tests/__init__.py`
- Create: `sensor/tests/tetragon_fixtures.py`
- Test: `sensor/tests/test_decoder.py`

**Interfaces:**

- Consumes: Tetragon `.proto` files from commit `2ea4b8357`.
- Produces: importable `GetEventsRequest`, `GetEventsResponse`, event
  messages, and `FineGuidanceSensorsStub`; fixture builders that return
  deterministic protobuf messages and raw bytes.

- [ ] **Step 1: Write the failing import and round-trip tests.**

  Add tests that import the generated modules, build a `ProcessExec` response,
  serialize it deterministically, parse it back, and assert the process PID,
  executable, start time, node name, and response time survive the round trip.

- [ ] **Step 2: Run the focused test to verify RED.**

  Run:

  ```bash
  cd /home/kylejudson/Dev/forest
  python3 -m unittest sensor.tests.test_decoder -v
  ```

  Expected: import failure because the adapter package and generated bindings
  do not yet exist.

- [ ] **Step 3: Add dependencies and generate bindings.**

  Record compatible `protobuf`, `grpcio`, and `grpcio-tools` dependencies in
  the two sensor requirement files. Generate Python bindings for
  `api/v1/tetragon/{bpf,capabilities,events,sensors,tetragon}.proto` using the
  Tetragon repository as the proto root and record the exact upstream commit,
  generation command, and package version in `manifest.json`. Do not hand-edit
  generated files.

- [ ] **Step 4: Add deterministic fixture builders and verify GREEN.**

  Implement fixture helpers for process start, process exit, generic trace,
  loader, and rate-limit responses. Re-run the focused test and then the
  existing Forest suite:

  ```bash
  python3 -m unittest sensor.tests.test_decoder -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

  Expected: both pass with no import warnings.

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/requirements.txt sensor/requirements-dev.txt sensor/tetragon sensor/tests
  git commit -m "feat: add Tetragon protobuf adapter fixtures"
  ```

## Task 2: Define adapter models and diagnostic vocabulary

**Files:**

- Create: `sensor/tetragon/models.py`
- Create: `sensor/tetragon/coverage.py`
- Test: `sensor/tests/test_coverage.py`

**Interfaces:**

- Consumes: generated protobuf `GetEventsResponse`, `SourceContext`, and
  `datetime` values from Task 1.
- Produces: `RawRecord`, `SourceDiagnostic`, `AdapterResult`, immutable
  `CoverageState`, `DiagnosticCode`, `AdapterConfig`, and `EventMapping`
  values used by all later tasks.

  ```python
  @dataclass(frozen=True)
  class AdapterConfig:
      source_kind: str
      allowed_source_ids: frozenset[str]
      policy_versions: dict[str, str]
      queue_limit: int

  @dataclass(frozen=True)
  class EventMapping:
      event_type: str
      policy_names: frozenset[str]
      required_fields: tuple[str, ...]
      action_time_field: str | None
      schema_version: str
  ```

- [ ] **Step 1: Write failing model and diagnostic tests.**

  Test construction of an immutable `RawRecord`, stable diagnostic payload
  hashing, serialization of an `AdapterResult`, and coverage transitions for
  `observed`, `degraded`, `quarantined`, `lost`, and `unsupported` states.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_coverage -v
  ```

  Expected: import failure for `sensor.tetragon.models`.

- [ ] **Step 3: Implement the minimal dataclasses and vocabulary.**

  Keep diagnostic codes explicit: `unauthenticated-source`, `malformed-input`,
  `unknown-schema`, `missing-required-field`, `missing-action-time`,
  `unsupported-policy`, `source-loss`, `reconnect-boundary`, `backpressure`,
  and `ambiguous-join-prerequisite`. Make diagnostic details string-keyed and
  JSON serializable.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_coverage -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/tetragon/models.py sensor/tetragon/coverage.py sensor/tests/test_coverage.py
  git commit -m "feat: define Tetragon adapter result models"
  ```

## Task 3: Implement identity, canonical bytes, and event IDs

**Files:**

- Create: `sensor/tetragon/identity.py`
- Test: `sensor/tests/test_identity.py`

**Interfaces:**

- Consumes: `RawRecord`, `SourceContext`, generated protobuf messages.
- Produces:

  ```python
  def process_ref(context: SourceContext, pid: int, start_time: str) -> str: ...
  def canonical_payload(response: GetEventsResponse) -> bytes: ...
  def event_id(record: RawRecord, event_type: str) -> str | None: ...
  def envelope_fields(record: RawRecord, event_time: str) -> dict[str, object]: ...
  ```

- [ ] **Step 1: Write failing identity tests.**

  Cover distinct boot IDs, distinct process start times, and distinct PIDs;
  assert that all produce different process references. Assert deterministic
  protobuf bytes and equal IDs for the same source, payload, and cursor; assert
  distinct cursor values produce distinct IDs. Assert generic records without a
  cursor return `None` rather than claiming collision-free redelivery identity.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_identity -v
  ```

  Expected: import failure for `sensor.tetragon.identity`.

- [ ] **Step 3: Implement the minimal identity functions.**

  Use deterministic protobuf serialization for canonical payload bytes. Build
  process references as `process:{machine_id}:{boot_id}:{pid}:{start_time}`.
  Hash source ID, event type, canonical payload, and cursor when present. For
  lifecycle events without a cursor, use the documented process-instance key
  only for the one start and one end record; return no generic ID when the
  identity cannot distinguish redeliveries from distinct identical events.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_identity -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/tetragon/identity.py sensor/tests/test_identity.py
  git commit -m "feat: add Tetragon CEM identity helpers"
  ```

## Task 4: Normalize process lifecycle events

**Files:**

- Create: `sensor/tetragon/normalizer.py`
- Create: `sensor/tetragon/process.py`
- Test: `sensor/tests/test_process_normalizer.py`

**Interfaces:**

- Consumes: `RawRecord`, identity helpers, and a `FileIdentityProvider`:

  ```python
  class FileIdentityProvider(Protocol):
      def sha256(self, path: str) -> str | None: ...
      def certificate(self, path: str) -> dict[str, str] | None: ...
  ```

- Produces: `TetragonNormalizer.normalize()` results for
  `process_exec` and `process_exit`.

- [ ] **Step 1: Write failing lifecycle tests.**

  Test that process exec maps executable, command line, cwd, UID, parent
  process, process reference, machine/boot/source identity, file hash, and
  `Process.start_time` into a `process.start` event. Test that process exit
  uses `ProcessExit.time` rather than response observation time. Test missing
  image hash and missing required process identity produce quarantine
  diagnostics. Test PID reuse across boot IDs does not share a process ref.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_process_normalizer -v
  ```

  Expected: import failure for the process normalizer.

- [ ] **Step 3: Implement minimal lifecycle normalization.**

  Add `process.py` helpers for extracting process fields and use an injected
  `FileIdentityProvider`; do not hash files inside the normalizer. Build event
  mappings compatible with Forest's existing `Event.from_mapping()` shape.
  Treat missing expected fields as explicit degradation and missing required
  fields as quarantine. Use the identity helper's lifecycle ID rules.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_process_normalizer -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/tetragon/normalizer.py sensor/tetragon/process.py sensor/tests/test_process_normalizer.py
  git commit -m "feat: normalize Tetragon process lifecycle"
  ```

## Task 5: Add timestamp gates and generic-event quarantine

**Files:**

- Modify: `sensor/tetragon/normalizer.py`
- Create: `sensor/tetragon/decoder.py`
- Test: `sensor/tests/test_decoder.py`
- Test: `sensor/tests/test_generic_normalizer.py`

**Interfaces:**

- Consumes: decoded `RawRecord`, policy mapping lookup, and the identity
  helpers.
- Produces:

  ```python
  def action_time(record: RawRecord, mapping: EventMapping) -> str | None: ...
  def normalize_generic(record: RawRecord, mapping: EventMapping) -> AdapterResult: ...
  ```

- [ ] **Step 1: Write failing timestamp and decoder tests.**

  Assert that a generic kprobe/tracepoint/uprobe with only
  `GetEventsResponse.time` returns `missing-action-time`, retains the raw
  payload hash, and emits no normal event. Assert a documented policy field
  carrying a source-native action timestamp is accepted. Assert malformed
  protobuf bytes and an unknown event variant produce bounded diagnostics.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_decoder sensor.tests.test_generic_normalizer -v
  ```

  Expected: missing decoder and generic normalization behavior.

- [ ] **Step 3: Implement deterministic decoding and timestamp gate.**

  Parse one response per call, retain the exact input bytes, reject trailing or
  malformed data, and classify unknown oneof variants. Implement the strict
  timestamp policy from the design spec; never fall back to receipt time.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_decoder sensor.tests.test_generic_normalizer -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/tetragon/decoder.py sensor/tetragon/normalizer.py sensor/tests/test_decoder.py sensor/tests/test_generic_normalizer.py
  git commit -m "feat: quarantine Tetragon events without action time"
  ```

## Task 6: Add versioned policy mappings and capability checks

**Files:**

- Create: `sensor/tetragon/policies.py`
- Create: `sensor/tests/test_policy_mappings.py`
- Modify: `sensor/tetragon/normalizer.py`

**Interfaces:**

- Consumes: decoded Tetragon records and adapter configuration.
- Produces:

  ```python
  @dataclass(frozen=True)
  class EventMapping:
      event_type: str
      policy_names: frozenset[str]
      required_fields: tuple[str, ...]
      action_time_field: str | None
      schema_version: str

  def mapping_for(record: RawRecord, config: AdapterConfig) -> EventMapping | None: ...
  ```

- [ ] **Step 1: Write failing mapping tests.**

  Test explicit mappings for `network.connect`, `network.accept`,
  `network.listen`, `dns.query`, `file.write`, `file.delete`,
  `file.exec-write`, and `module.load`. Test that an enabled but unknown policy
  is `unsupported-policy`, a known policy missing a required argument is
  `missing-required-field`, and an inactive policy cannot emit the CEM event.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_policy_mappings -v
  ```

  Expected: import failure for `sensor.tetragon.policies`.

- [ ] **Step 3: Implement mapping declarations and capability gates.**

  Use immutable mapping declarations keyed by policy name and schema version.
  Map only fields whose source argument schema is documented. Keep
  `network.accept.initiator` unset; the Forest both-ends stage owns it. Treat
  build ID as insufficient for module SHA-256 and preserve that degradation.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_policy_mappings -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/tetragon/policies.py sensor/tetragon/normalizer.py sensor/tests/test_policy_mappings.py
  git commit -m "feat: gate Tetragon CEM mappings by policy capability"
  ```

## Task 7: Implement network, file, executable-write, and module mappings

**Files:**

- Modify: `sensor/tetragon/normalizer.py`
- Create: `sensor/tetragon/enrichment.py`
- Create: `sensor/tests/test_network_mappings.py`
- Create: `sensor/tests/test_file_mappings.py`
- Create: `sensor/tests/test_module_mappings.py`

**Interfaces:**

- Consumes: `EventMapping`, `RawRecord`, `FileIdentityProvider`, and identity
  helpers from Tasks 3–6.
- Produces: CEM mappings with local process truth and explicit expected-field
  degradation; no Forest cross-source attribution.

- [ ] **Step 1: Write failing mapping tests.**

  Test normalized network five-tuples and protocol; local-only accept events;
  DNS query names; file write/delete paths; executable-write classification for
  ELF magic, shebang, and ordinary files; and module path/hash handling. Test
  missing hash, deletion kind, certificate, provenance, and operation context
  remain explicit degradation rather than guessed values.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_network_mappings sensor.tests.test_file_mappings sensor.tests.test_module_mappings -v
  ```

  Expected: import failure for the mapping test modules and enrichment helpers.

- [ ] **Step 3: Implement minimal capability-gated mappers.**

  Keep socket and file argument extraction separate from CEM field assembly.
  Require action time and CEM-required fields before emitting. Use injected
  file identity/classification services; do not read arbitrary file contents
  or infer operation provenance from executable names.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_network_mappings sensor.tests.test_file_mappings sensor.tests.test_module_mappings -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/tetragon/normalizer.py sensor/tetragon/enrichment.py sensor/tests/test_network_mappings.py sensor/tests/test_file_mappings.py sensor/tests/test_module_mappings.py
  git commit -m "feat: map gated Tetragon Linux observations"
  ```

## Task 8: Implement authenticated streaming, reconnect, loss, and backpressure

**Files:**

- Create: `sensor/tetragon/receiver.py`
- Create: `sensor/tetragon/transport.py`
- Create: `sensor/tests/test_receiver.py`
- Modify: `sensor/tetragon/models.py`
- Modify: `sensor/tetragon/coverage.py`

**Interfaces:**

- Consumes: generated `FineGuidanceSensorsStub`, TLS/token configuration, and
  `RawRecord` construction.
- Produces:

  ```python
  class TetragonTransport(Protocol):
      def events(self, request: GetEventsRequest) -> Iterable[GetEventsResponse]: ...

  class Authenticator(Protocol):
      def authenticate(self, peer: str, metadata: tuple[tuple[str, str], ...]) -> SourceContext: ...

  class Receiver:
      def records(self) -> Iterator[RawRecord | SourceDiagnostic]: ...
  ```

- [ ] **Step 1: Write failing transport tests.**

  Use a small fake transport, not mocks of adapter logic, to test successful
  streaming, unauthenticated peers, malformed responses, disconnect/reconnect
  with backoff, cursor resume, throttling/loss diagnostics, bounded queue
  overflow, and explicit reconnect boundaries when no cursor exists.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_receiver -v
  ```

  Expected: import failure for the receiver and transport interfaces.

- [ ] **Step 3: Implement minimal receiver behavior.**

  Authenticate before yielding records, preserve response bytes and receipt
  time, reconnect only according to bounded backoff, resume from a cursor when
  present, and yield a diagnostic rather than silently ending on loss or queue
  overflow. Keep transport concerns separate from normalization.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_receiver -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add sensor/tetragon/receiver.py sensor/tetragon/transport.py sensor/tetragon/models.py sensor/tetragon/coverage.py sensor/tests/test_receiver.py
  git commit -m "feat: receive authenticated Tetragon event streams"
  ```

## Task 9: Assemble the adapter runner and Forest handoff

**Files:**

- Create: `sensor/tetragon/runner.py`
- Create: `sensor/tests/test_runner.py`
- Modify: `sensor/tetragon/__init__.py`
- Modify: `sensor/README.md`

**Interfaces:**

- Consumes: `Receiver.records()`, `TetragonNormalizer.normalize()`, and
  `CoverageState` from Tasks 2–8.
- Produces:

  ```python
  class AdapterRunner:
      def run(self) -> Iterator[dict[str, object] | SourceDiagnostic]: ...
  ```

  The runner emits normalized event mappings and diagnostics in input order
  while preserving each record's source cursor and raw-payload hash.

- [ ] **Step 1: Write failing orchestration tests.**

  Feed a fake receiver with process start, process end, generic missing-time,
  and source-loss records. Assert the runner emits two valid lifecycle events,
  one diagnostic for the quarantined generic record, and one loss diagnostic in
  the same source order. Assert no raw payload body is exposed in ordinary
  event fields.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_runner -v
  ```

  Expected: import failure for `AdapterRunner`.

- [ ] **Step 3: Implement minimal orchestration.**

  Compose receiver, normalizer, and coverage sink through constructor
  injection. Keep the runner free of event-specific mapping logic. Export only
  the stable adapter interfaces from `sensor/tetragon/__init__.py`.

- [ ] **Step 4: Run focused and full tests for GREEN.**

  ```bash
  python3 -m unittest sensor.tests.test_runner -v
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 5: Document and commit.**

  Document installation, Tetragon RPC configuration, source authentication,
  supported event mappings, quarantine behavior, metrics, raw-record retention,
  and the deferred register in `sensor/README.md`, then run:

  ```bash
  git add sensor/tetragon sensor/README.md sensor/tests/test_runner.py
  git commit -m "feat: assemble Forest Tetragon adapter"
  ```

## Task 10: Contract, integration, and operational verification

**Files:**

- Create: `sensor/tests/test_tetragon_contract.py`
- Create: `sensor/tests/test_tetragon_reconnect.py`
- Modify: `sensor/tetragon/README.md`
- Modify: `sensor/README.md`

**Interfaces:**

- Consumes: complete adapter output from Task 9 and the pinned Forest CEM
  revision.
- Produces: release evidence for the first-phase acceptance criteria; no new
  production interface.

- [ ] **Step 1: Write failing contract and operational tests.**

  Assert every emitted event has source, machine, boot, type, ID, received
  time, and required process references. Assert start/end action times are
  correct. Assert generic missing-time records never enter the normal event
  stream. Assert duplicate delivery is stable, PID reuse is isolated, and
  reconnect/loss/backpressure diagnostics are visible.

- [ ] **Step 2: Run RED.**

  ```bash
  python3 -m unittest sensor.tests.test_tetragon_contract sensor.tests.test_tetragon_reconnect -v
  ```

  Expected: any missing release behavior fails with a specific assertion; do
  not weaken tests to accommodate an implementation shortcut.

- [ ] **Step 3: Implement only the minimal fixes exposed by the tests.**

  Keep changes within the adapter boundary. If a test demonstrates a missing
  source fact rather than an adapter defect, record the corresponding deferred
  item (`T-001` through `T-016`) and keep the event quarantined.

- [ ] **Step 4: Run all Forest tests and record evidence.**

  ```bash
  cd /home/kylejudson/Dev/forest
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  python3 -m unittest discover -s sensor/tests -p 'test_*.py' -v
  ```

  Expected: all existing and adapter tests pass with no unexpected warnings.
  Record dependency versions, fixture source commit, supported event mappings,
  and known quarantined families in the adapter README.

- [ ] **Step 5: Commit the verification evidence.**

  ```bash
  git add sensor/tests sensor/README.md sensor/tetragon/README.md
  git commit -m "test: verify Forest Tetragon adapter contract"
  ```

## Deferred work that must remain out of this implementation

The design's deferred register is part of the deliverable. Do not silently
expand this plan to implement it. In particular, this plan does not implement
T-001/T-002 generic action timestamps or replay cursors, T-008/T-009 Forest
joins and NAT-aware correlation, T-010 exactly-once effects, T-011/T-012
Linux semantic operation sources, T-013 Windows collectors, T-014 macOS
collectors, or T-016 final production hardening. Those items require their
documented triggers and separate testable plans.

## Final verification checklist

- [ ] Every handwritten production function has a test that was observed to
  fail before its implementation was written.
- [ ] Focused tests pass after each task's GREEN step.
- [ ] The full existing Forest test suite passes after every task that touches
  shared code and at the final verification task.
- [ ] No generic event uses observation or receipt time as CEM action time.
- [ ] Required-field failures are quarantined and diagnosed.
- [ ] Source loss, reconnect boundaries, and backpressure are visible.
- [ ] The adapter never invents cross-source initiator, service, operation,
  provenance, certificate, or component identity.
- [ ] The deferred register remains synchronized with the design spec.
- [ ] Tetragon source changes are proposed separately and only for facts the
  adapter cannot obtain elsewhere.
