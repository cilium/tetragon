## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* The default value of metrics scrape interval in both agent and operator
  ServiceMonitors (`tetragon.prometheus.serviceMonitor.scrapeInterval` and
  `tetragonOperator.prometheus.serviceMonitor.scrapeInterval` values
  respectively) is changed from 10s to 60s.

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* TBD

### Metrics

* TBD
