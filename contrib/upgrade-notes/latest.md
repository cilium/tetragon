## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* The `--enable-export-aggregation`, `--export-aggregation-window-size` and
  `--export-aggregation-buffer-size` flags were removed. Aggregation was a no-op
  that forwarded every event unchanged. Tetragon now fails to start if these
  flags are passed on the command line, including through the Helm
  `tetragon.extraArgs` or `tetragon.argsOverride` values, so remove them before
  upgrading. If they are set in a configuration file, a configuration directory
  (such as the `tetragon-config` ConfigMap), or a `TETRAGON_` environment
  variable, they are ignored.
* Tetragon now rejects a `--field-filters` entry that repeats a key, for
  example two `fields` members in one filter, and fails to start. Earlier
  versions kept the last value. Remove the duplicate before upgrading.

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* The TracingPolicy CRD now limits the number of hooks that can be defined within a single policy to a maximum of 128. If this limit is exceeded, the policy will be rejected by the Kubernetes API server. To resolve this, split your hooks across multiple TracingPolicies.

### Events (protobuf API)

* The `AggregationOptions` and `AggregationInfo` messages were removed, along
  with the `GetEventsRequest.aggregation_options` and
  `GetEventsResponse.aggregation_info` fields. The field numbers and names are
  reserved. Clients sending `aggregation_options` are unaffected on the wire,
  but code referencing these types or fields needs to be updated.

### Metrics

* TBD
