## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* Enabling ancestors for process events is now configured by a new `--enable-ancestors` flag.
  The following flags are being deprecarted in this (1.5) and are scheduled for removal in the next (1.6):
   * `--enable-process-ancestors`
   * `--enable-process-kprobe-ancestors`
   * `--enable-process-tracepoint-ancestors`
   * `--enable-process-uprobe-ancestors`
   * `--enable-process-lsm-ancestors`

### Agent Options

* TBD

### Helm Values

* The default value of metrics scrape interval in both agent and operator
  ServiceMonitors (`tetragon.prometheus.serviceMonitor.scrapeInterval` and
  `tetragonOperator.prometheus.serviceMonitor.scrapeInterval` values
  respectively) is changed from 10s to 60s.

* OciHookSetup section is removed after being deprecated in 1.2.

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* TBD

### Metrics

* TBD
