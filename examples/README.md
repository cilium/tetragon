# Examples

This folder contains examples of resources YAML and configuration files.

- See [`tracingpolicy`](tracingpolicy) directory for examples on TracingPolicy
  custom resources. These examples are written manually. Add more examples if
  you feel like it.
- See [`configuration`](configuration) directory for an example of
  configuration file for Tetragon and and directory structure.

## How to deploy a TracingPolicy example

Let's take `tracingpolicy/write.yaml` arbitrarly as an example.

### Kubernetes

```shell
kubectl apply -f tracingpolicy/write.yaml
```

### Standalone

Pass the file with the `--config-file` flag:
```shell
sudo ./tetragon --bpf-lib bpf/objs --config-file tracingpolicy/write.yaml
```

### Tetra CLI

Or use `tetra` CLI against a running Tetragon instance:
```shell
tetra tracingpolicy add tracingpolicy/write.yaml
```

