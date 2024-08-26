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

In a [Kubernetes installation]({{< ref "/docs/installation/kubernetes" >}}), **metrics are enabled by default** and
exposed via the endpoint `/metrics`. The `tetragon` service exposes the Tetragon Agent metrics on port `2112`, and the
`tetragon-operator-metrics` service the Tetragon Operator metrics on port `2113`.

You can change the port via Helm values:

```yaml
tetragon:
  prometheus:
    port: 2222 # default is 2112
tetragonOperator:
  prometheus:
    port: 3333 # default is 2113
```

Or entirely disable the metrics server:

```yaml
tetragon:
  prometheus:
    enabled: false # default is true
tetragonOperator:
  prometheus:
    enabled: false # default is true
```

### Non-Kubernetes

In a non-Kubernetes installation, **metrics are disabled by default**. You can enable them by setting the metrics server
address of the Tetragon Agent to, for example, `:2112`, via the `--metrics-server` flag.

If using [systemd]({{< ref "/docs/installation/package" >}}), set the `metrics-address` entry in a file under the
`/etc/tetragon/tetragon.conf.d/` directory.

## Verify that metrics are exposed

To verify that the metrics server has started, check the logs of the Tetragon components.
Here's an example for the Tetragon Agent, running on Kubernetes:

```shell
kubectl -n <tetragon-namespace> logs ds/tetragon
```

The logs should contain a line similar to the following:
```
time="2023-09-22T23:16:24+05:30" level=info msg="Starting metrics server" addr="localhost:2112"
```

To see what metrics are exposed, you can access the metrics endpoint directly.
In Kubernetes, forward the metrics port:

```shell
kubectl -n <tetragon-namespace> port-forward svc/tetragon 2112:2112
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

## Enable Prometheus ServiceMonitors

Typically, metrics are scraped by Prometheus or another compatible agent (for example OpenTelemetry Collector), stored
in Prometheus or another compatible database, then queried and visualized for example using Grafana.

In Kubernetes, you can install Prometheus and Grafana using the [Kube-Prometheus-Stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) Helm chart. This Helm chart includes the
[Prometheus Operator](https://prometheus-operator.dev/),
which allows you to configure Prometheus via Kubernetes custom resources.

```shell
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
```

{{< note >}}

  By default, the Prometheus Operator only discovers `PodMonitors` and `ServiceMonitors` within its namespace, that are
  labeled with the same release tag as the prometheus-operator release.

  Hence, you need to configure Prometheus to also scrape data from Tetragon's `ServiceMonitor` resources, which don't
  fulfill those conditions. This is configurable when installing the
  [Kube-Prometheus-Stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) by setting the `serviceMonitorSelectorNilUsesHelmValues` flag.

{{< /note >}}

Refer to the official [Kube-Prometheus-Stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) documentation for more details.

Tetragon comes with default `ServiceMonitor` resources containing the scrape confguration for the Agent and Operator.
You can enable it via Helm values:

```yaml
tetragon:
  prometheus:
    serviceMonitor:
      enabled: true
tetragonOperator:
  prometheus:
    serviceMonitor:
      enabled: true
```

To ensure that Prometheus has detected the Tetragon metrics endpoints, you can check the Prometheus targets:

1. Access the Prometheus UI.
2. Navigate to the "Status" tab and select "Targets".
3. Verify that the Tetragon metric endpoints are listed and their status is `UP`.