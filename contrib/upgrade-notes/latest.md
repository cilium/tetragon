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

#### TracingPolicy (k8s CRD)

* TBD

#### Events (protobuf API)

* TBD

#### Metrics

* TBD
