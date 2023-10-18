---
title: "Metrics"
icon: "overview"
weight: 2
description: "Documentation for Tetragon metrics"
---

Tetragon's metrics are exposed to the system through an HTTP endpoint. These
are used to expose event summaries and information about the state of the
Tetragon agent.

## Kubernetes

Tetragon pods exposes a metrics endpoint by default. The chart also creates a
service named `tetragon` that exposes metrics on the specified port.

### Getting metrics port

Check if the `tetragon` service exists:

```shell-session
kubectl get services tetragon -n kube-system
```

The output should be similar to:
```
NAME       TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)     AGE
tetragon   ClusterIP   10.96.54.218   <none>        2112/TCP    3m
```

{{< note >}}
In the previous output it shows, 2112 is the port on which the service is
listening. It is also the port on which the Tetragon metrics server listens
with the default Helm values.
{{< /note >}}

### Port Forwarding

To forward the metrics port locally, use `kubectl port forward`:

```shell-session
kubectl -n kube-system port-forward service/tetragon 2112:2112
```

## Systemd and Local Packages

By default, metrics are disabled when following systemd installation or
using release images to install locally. The metrics can be enabled using `--metrics-server`
flag, by specifying the address.

Alternatively, the [examples/configuration/tetragon.yaml](https://github.com/cilium/tetragon/blob/main/examples/configuration/tetragon.yaml)
file contains example entries showing the defaults for the address of
metrics-server. Local overrides can be created by editing and copying this file
into `/etc/tetragon/tetragon.yaml`, or by editing and copying "drop-ins" from
the [examples/configuration/tetragon.conf.d](https://github.com/cilium/tetragon/tree/main/examples/configuration/tetragon.conf.d)
directory into the `/etc/tetragon/tetragon.conf.d/` subdirectory. The latter is
generally recommended.

### Set Metrics Address

Run `sudo tetragon --metrics-server localhost:2112` to set metrics address to `localhost:2112` and export metrics.

```shell-session
sudo tetragon --metrics-server localhost:2112
```

The output should be similar to this:

```
time="2023-09-21T13:17:08+05:30" level=info msg="Starting tetragon"
version=v0.11.0
time="2023-09-21T13:17:08+05:30" level=info msg="config settings"
config="mapeased
time="2023-09-22T23:16:24+05:30" level=info msg="Starting metrics server"
addr="localhost:2112"
[...]
time="2023-09-21T13:17:08+05:30" level=info msg="Listening for events..."
```

Alternatively, a file named `server-address` can be created in `etc/tetragon/tetragon.conf.d/metrics-server` with content specifying
a port like this `localhost:2112`, or any port of your choice as mentioned
above.

## Fetch the Metrics

After the metrics are exposed, either by port forwarding in case of
Kubernetes installation or by setting metrics address in case of Package
installation, the metrics can be fetched using
`curl` on `localhost:2112/metrics`:

```shell-session
curl localhost:2112/metrics
```

The output should be similar to this:
```
# HELP promhttp_metric_handler_errors_total Total number of internal errors encountered by the promhttp metric handler.
# TYPE promhttp_metric_handler_errors_total counter
promhttp_metric_handler_errors_total{cause="encoding"} 0
promhttp_metric_handler_errors_total{cause="gathering"} 0
# HELP tetragon_errors_total The total number of Tetragon errors. For internal use only.
# TYPE tetragon_errors_total counter
[...]
```
