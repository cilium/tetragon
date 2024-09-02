## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

#### Agent Options

* TBD

#### Helm Values

* Tetragon container now uses the gRPC liveness probe by default. To continue using "tetra status" for liveness probe,
specify `tetragon.livenessProbe` Helm value. For example:
```yaml
tetragon:
  livenessProbe:
     timeoutSeconds: 60
     exec:
       command:
       - tetra
       - status
       - --server-address
       - "54321"
       - --retries
       - "5"
```
* Deprecated `tetragon.skipCRDCreation` Helm value is removed. Use `crds.installMethod=none` instead.

* `tetragon.ociHookSetup` Helm value is deprecated. Use `tetragon.rthooks` instead.

#### TracingPolicy (k8s CRD)

* TBD

#### Events (protobuf API)

* Sensor managing methods have been deprecated:
  * `ListSensors`
  * `EnableSensor`
  * `DisableSensor`
  * `RemoveSensor`

#### Metrics

* `tetragon_policyfilter_metrics_total` metric is renamed to `tetragon_policyfilter_operations_total`, and its `op`
  label is renamed to `operation`.
* `tetragon_missed_events_total` metric is renamed to `tetragon_bpf_missed_events_total`.
* Metrics related to ring buffer and events queue are renamed:
  * `tetragon_ringbuf_perf_event_errors_total` -> `tetragon_observer_ringbuf_errors_total`
  * `tetragon_ringbuf_perf_event_received_total` -> `tetragon_observer_ringbuf_events_received_total`
  * `tetragon_ringbuf_perf_event_lost_total` -> `tetragon_observer_ringbuf_events_lost_total`
  * `tetragon_ringbuf_queue_received_total` -> `tetragon_observer_ringbuf_queue_events_received_total`
  * `tetragon_ringbuf_queue_lost_total` -> `tetragon_observer_ringbuf_queue_events_lost_total`
* `tetragon_msg_op_total` metric is removed. `tetragon_observer_ringbuf_queue_events_received_total` or
  `tetragon_events_total` can be used as a replacement, depending on the use case.
