---
title: "Metrics"
weight: 7
description: "Learn how to configure and access Prometheus metrics."
aliases: ["/docs/concepts/metrics"]
---

Tetragon exposes a number of Prometheus metrics that can be used for two main purposes:

1. Monitoring the health of Tetragon itself
2. Monitoring the activity of processes observed by Tetragon

For the full list, refer to [metrics reference]({{< ref "/docs/reference/metrics" >}}).

## Enable/Disable Metrics

### Kubernetes

In a [Kubernetes installation]({{< ref "/docs/installation/kubernetes" >}}), metrics are enabled by default and exposed
via `tetragon` service at endpoint `/metrics` on port `2112`.

You can change the port via Helm values:

```yaml
tetragon:
  prometheus:
    port: 2222 # default is 2112
```

Or entirely disable the metrics server:

```yaml
tetragon:
  prometheus:
    enabled: false # default is true
```

### Non-Kubernetes

In a non-Kubernetes installation, metrics are disabled by default. You can enable them by setting the metrics server
address, for example `:2112`, via the `--metrics-server` flag.

If using [systemd]({{< ref "/docs/installation/package" >}}), set the `metrics-address` entry in a file under the
`/etc/tetragon/tetragon.conf.d/` directory.

## Verify that metrics are exposed

To verify that the metrics server has started, check the logs of the Tetragon Agent.
In Kubernetes, run:

```shell
kubectl -n kube-system logs ds/tetragon
```

The logs should contain a line similar to the following:
```
time="2023-09-22T23:16:24+05:30" level=info msg="Starting metrics server" addr="localhost:2112"
```

To see what metrics are exposed, you can access the metrics endpoint directly.
In Kubernetes, forward the metrics port:

```shell
kubectl -n kube-system port-forward svc/tetragon 2112:2112
```

Access `localhost:2112/metrics` endpoint either in a browser or for example using `curl`.
You should see a list of metrics similar to the following:
```
# HELP promhttp_metric_handler_errors_total Total number of internal errors encountered by the promhttp metric handler.
# TYPE promhttp_metric_handler_errors_total counter
promhttp_metric_handler_errors_total{cause="encoding"} 0
promhttp_metric_handler_errors_total{cause="gathering"} 0
# HELP tetragon_errors_total The total number of Tetragon errors. For internal use only.
# TYPE tetragon_errors_total counter
[...]
```

## Configure labels on events metrics

Depending on the workloads running in the environment, [Events Metrics]({{< ref "/docs/reference/metrics#tetragon-events-metrics" >}})
may have very high cardinality. This is particularly likely in Kubernetes environments, where each pod creates
a separate timeseries. To avoid overwhelming Prometheus, Tetragon provides an option to choose which labels are
populated in these metrics.

You can configure the labels via Helm values or the `--metrics-label-filter` flag. Set the value to a comma-separated
list of enabled labels:

```yaml
tetragon:
  prometheus:
    metricsLabelFilter: "namespace,workload,binary" # "pod" label is disabled
```

## Scrape metrics

Typically, metrics are scraped by Prometheus or another compatible agent (for example OpenTelemetry Collector), stored
in Prometheus or another compatible database, then queried and visualized for example using Grafana.

In Kubernetes, you can install Prometheus and Grafana using the `kube-prometheus-stack` Helm chart:

```shell
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
```

The `kube-prometheus-stack` Helm chart includes [Prometheus Operator](https://prometheus-operator.dev/), which allows
you to configure Prometheus via Kubernetes custom resources. Tetragon comes with a default `ServiceMonitor` resource
containing the scrape confguration. You can enable it via Helm values:

```yaml
tetragon:
  prometheus:
    serviceMonitor:
      enabled: true
```
