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
  example two `fields` members in one filter. Earlier versions kept the last
  value. The Helm `tetragon.fieldFilters` value, the `tetragon-config`
  ConfigMap and the `TETRAGON_FIELD_FILTERS` environment variable set the same
  option. With JSON export on, the Helm default, a repeated key stops Tetragon
  at startup. Remove the duplicate before upgrading.

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* The TracingPolicy CRD now limits the number of hooks that can be defined within a single policy to a maximum of 128. If this limit is exceeded, the policy will be rejected by the Kubernetes API server. To resolve this, split your hooks across multiple TracingPolicies.
* The TracingPolicy CRD now restricts `returnArgAction` to `TrackSock` and
  `UntrackSock`. Since v1.8.0 the agent fails to load a policy with any other
  action; now the Kubernetes API server and the agent's policy parser reject
  it up front. The check is case-sensitive, so change spellings such as
  `tracksock` and remove an empty `returnArgAction: ""`.
* `resolve` paths are now checked more strictly when a policy is loaded. A
  leading or trailing dot (`.mm.pgd`, `file.f_path.`) and a field name right
  after an index (`a[0]b`) were accepted before and are now rejected. Write
  them as `mm.pgd`, `file.f_path` and `a[0].b`.

* `matchBinaries` and `matchParentBinaries` selectors must now have at least one
  entry in `values`, and entries must not be empty strings. Policies that
  do not meet these requirements are rejected.

### Events (protobuf API)

* The `AggregationOptions` and `AggregationInfo` messages were removed, along
  with the `GetEventsRequest.aggregation_options` and
  `GetEventsResponse.aggregation_info` fields. The field numbers and names are
  reserved. Clients sending `aggregation_options` are unaffected on the wire,
  but code referencing these types or fields needs to be updated.

### Metrics

* TBD
