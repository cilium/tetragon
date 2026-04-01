## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.
See the [Stack Traces](https://tetragon.io/docs/concepts/tracing-policy/selectors/#stack-traces) documentation for stack trace migration.

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
  in `ProcessKprobe` events. See the [Stack Traces](https://tetragon.io/docs/concepts/tracing-policy/selectors/#stack-traces) documentation and `examples/tracingpolicy/stack_traces.yaml`.
* The already-deprecated `EnableTracingPolicy` and `DisableTracingPolicy` gRPC
  methods have been actually enforced to return an error when used. For now, `enable-deprecated-tracingpolicy-grpc`
  option has been introduced to restore the old behavior. The next release will remove the deprecated methods.

### Metrics

* TBD
