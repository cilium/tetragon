## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* It's now supported to run multiple Tetragon operator replicas simultaneously. Enable it by setting `tetragonOperator.replicas=2` and `tetragonOperator.failoverLease.enabled=true`.
* `tetragonOperator.strategy` now sets a default `rollingUpdate` strategy (`maxSurge=1`, `maxUnavailable=0`) to reduce downtime during an upgrade.
* The Tetragon operator Deployment now sets a default `podAntiAffinity` (`preferredDuringSchedulingIgnoredDuringExecution`) to improve the Pod distribution (if possible), without enforcing it to avoid being stuck during upgrades on single or two node clusters.

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* TBD

### Metrics

* `tetragon_map_errors_total` metric is replaced by `map_errors_update_total` and `map_errors_delete_total`.
