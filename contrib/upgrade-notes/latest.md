## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* The TracingPolicy CRD now limits the number of hooks that can be defined within a single policy to a maximum of 128. If this limit is exceeded, the policy will be rejected by the Kubernetes API server. To resolve this, split your hooks across multiple TracingPolicies.

### Events (protobuf API)

* TBD

### Metrics

* TBD
