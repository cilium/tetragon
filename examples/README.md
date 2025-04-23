# Examples

This folder contains examples of resources YAML and configuration files.

- The [`policylibrary`](policylibrary) directory contains example policies
  (TracingPolicy custom resources). These examples are generally well
  documented, either in the file itself or in Tetragon documentation.
- See [`tracingpolicy`](tracingpolicy) directory for more policy examples.
  The policies in this directory are provided as a samples only, and do not provide any security
  observability guarantees. Users are strongly encouraged to evaluate the functionality defined in
  this policy and make any modifications necessary to achieve their desired security posture.
- See [`configuration`](configuration) directory for an example of
  configuration file for Tetragon and and directory structure.

## How to deploy a TracingPolicy example

Let's take `tracingpolicy/write.yaml` arbitrarly as an example.

### Kubernetes

```shell
kubectl apply -f tracingpolicy/write.yaml
```

### Standalone

Pass the file with the `--tracing-policy` flag:
```shell
sudo ./tetragon --bpf-lib bpf/objs --tracing-policy tracingpolicy/write.yaml
```

### Tetra CLI

Or use `tetra` CLI against a running Tetragon instance:
```shell
tetra tracingpolicy add tracingpolicy/write.yaml
```

