## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* `FollowFD`, `UnfollowFD`, and `CopyFD` actions are being deprecarted in this (1.4) and are
  scheduled for removal in the next (1.5)

### Events (protobuf API)

* TBD

### Metrics

* `tetragon_map_errors_total` metric is replaced by `map_errors_update_total` and `map_errors_delete_total`.
