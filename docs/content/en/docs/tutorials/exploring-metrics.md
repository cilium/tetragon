---
title: "Exploring Tetragon Metrics"
weight: 1
icon: "overview"
description: "Enable metrics on Tetragon and discover available metrics."
---

In this tutorial, we will deploy Tetragon as a standalone container (outside
kubernetes) and a monitoring stack with Prometheus and Grafana to inspect metrics
exposed by Tetragon.
In the last part, we will also show how to access metrics when Tetragon is
deployed in a Kubernetes cluster.

### Explore metrics on the workstation with Docker

#### requirements

* Docker: either [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* [Docker compose plugin](https://docs.docker.com/compose/install/)

#### Create Configuration Files

First of all, you need a `docker-compose.yaml` that describe containers you would
like to launch:

* Tetragon
* Prometheus: fetch and store metrics
* Grafana: display metrics in fancy dashboard

```yaml
---
# docker-compose.yaml
version: "2.2"
services:
  tetragon:
    image: quay.io/cilium/tetragon:v0.11.0
    command: ["/usr/bin/tetragon", "--metrics-server", ":2112"]
    pid: "host"
    userns_mode: "host"
    privileged: true
    volumes:
      - /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf

  prometheus:
    image: quay.io/prometheus/prometheus:v2.47.0
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus:/prometheus
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana-oss:10.1.2
    volumes:
      - ./datasource.yaml:/etc/grafana/provisioning/datasources/datasource.yaml
      - grafana-data:/var/lib/grafana
    ports:
      - "3000:3000"

volumes:
    prometheus:
    grafana-data:
```

You will need two additional files:

* `prometheus.yml`: configure link between Tetragon and Prometheus
* `datasource.yaml`: configure link between Prometheus and Grafana

In the prometheus configuration, you need to specify the endpoint where metrics
are available. As we are using docker compose we can simply use the name of the
service `tetragon` to reach the Tetragon container from Prometheus:

```yaml
---
# prometheus.yml
global:
  scrape_interval: 30s
  scrape_timeout: 10s
  evaluation_interval: 1m
scrape_configs:
- job_name: tetragon
  static_configs:
  - targets:
    - tetragon:2112
```


For the Grafana configuration, the Prometheus container is also available with
the name of the service:

```yaml
---
# datasource.yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    isDefault: true
    url: http://prometheus:9090/
```

You should now have 3 files:

* `docker-compose.yaml`
* `prometheus.yml`
* `datasource.yaml`

#### Launch the composition

Just launch the composition with the `up` sub command:

```shell
docker compose up -d
```

You should be able to access:

* Prometheus: [http://localhost:9090](http://localhost:9090)
* Grafana: [http://localhost:3000](http://localhost:3000) (login: admin,
  password: admin)

Metrics will be stored on a docker volume, you can cleanup data and container with:

```shell
docker compose down --volumes
```

Or just remove container with `docker compose down`.

### Access Metrics in a Kubernetes cluster

If Tetragon is deployed in the `kube-system`, you can forward the metrics port
locally from the first Tetragon Pod with:

```shell
kubectl port-forward -n kube-system ds/tetragon 2112:2112
```

and then access metrics locally from [http://localhost:2112/metrics](http://localhost:2112/metrics).

If the [Prometheus
Operator](https://github.com/prometheus-operator/prometheus-operator) is deployed in
your cluster. You can "configure" Prometheus to fetch metrics from tetragon with
a `PodMonitor` object:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: monitor-tetragon
  namespace: kube-system # Namespace where Tetragon is deployed
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: tetragon # Adjust selector based on your config
      app.kubernetes.io/name: tetragon
  podMetricsEndpoints:
  - targetPort: 2112
```
