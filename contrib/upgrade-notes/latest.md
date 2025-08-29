## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* The `tetragonOperator.securityContext` field has been deprecated in favor of `tetragonOperator.containerSecurityContext` for clarity. The old field is still supported for backward compatibility but might be removed in a future release. Users should migrate their configurations to use the new field.

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* TBD

### Metrics

* TBD
