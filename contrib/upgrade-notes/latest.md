## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* The legacy stacktrace-tree API has been removed: `GetStackTraceTree` gRPC,
  `tetra stacktrace-tree` CLI command, and related types (`GetStackTraceTreeRequest`,
  `GetStackTraceTreeResponse`, `stack.proto`). Use TracingPolicy with
  `kernelStackTrace` and `userStackTrace` in the Post action to get stack traces
  in `ProcessKprobe` events. See `examples/tracingpolicy/stack_traces.yaml`.

### Metrics

* TBD
