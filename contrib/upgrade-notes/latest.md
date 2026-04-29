## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* `returnArgAction` no longer accepts `Post`. Use `returnArg` to include the
  return value in events, and omit `returnArgAction` for the default return-value
  behavior. Only `TrackSock` and `UntrackSock` are supported. Existing policies
  that set `returnArgAction: "Post"` should remove the field.

### Events (protobuf API)

* TBD

### Metrics

* TBD
