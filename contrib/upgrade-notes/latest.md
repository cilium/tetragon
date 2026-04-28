## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.
See the [Stack Traces](https://tetragon.io/docs/concepts/tracing-policy/selectors/#stack-traces) documentation for stack trace migration.

* TBD

### Agent Options

* TBD

### Helm Values

* Change the default server-address of the agent to from `localhost:54321` to `/var/run/tetragon/tetragon.sock`.
  This socket is also available for root users under the same path on the node. Update this address in all third-party programs that connect to the agent.

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

* Kprobe and uprobe merge metrics have been consolidated.
  The following metrics were removed:
  - `tetragon_generic_kprobe_merge_errors_total`
  - `tetragon_generic_kprobe_merge_ok_total`
  They are replaced by `tetragon_generic_kprobe_merge_total` which includes a `status` label with values `ok` or `error`.
  The new metric also includes labels `curr_type`, `prev_type` (either `enter` or `exit`), `curr_fn`, and `prev_fn`.
