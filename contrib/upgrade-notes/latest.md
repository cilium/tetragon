## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* The `returnArgAction` field in kprobes no longer accepts `Post` as a valid value.
  Previously, setting `returnArgAction: "Post"` was silently ignored (no-op). Now it
  will cause a validation error when loading the TracingPolicy. If your policies use
  `returnArgAction: "Post"`, simply remove the field as it had no effect.

### Events (protobuf API)

* TBD

### Metrics

* TBD
