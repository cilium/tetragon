---
title: "Configure Tetragon"
linkTitle: "Configuration"
weight: 5
---

Depending on your deployment mode, Tetragon configuration can be changed by:

{{< tabpane lang=shell >}}

{{< tab Kubernetes >}}
kubectl edit cm -n kube-system tetragon-config
# Change your configuration setting, save and exit
# Restart Tetragon daemonset
kubectl rollout restart -n kube-system ds/tetragon
{{< /tab >}}
{{< tab Docker >}}
# Change configuration inside /etc/tetragon/ then restart container.
# Example:
#   1. As a privileged user, write to the file /etc/tetragon/tetragon.conf.d/export-file
#      the path where to export events, example "/var/log/tetragon/tetragon.log"
#   2. Bind mount host /etc/tetragon into container /etc/tetragon
# Tetragon events will be exported to /var/log/tetragon/tetragon.log
echo "/var/log/tetragon/tetragon.log" > /etc/tetragon/tetragon.conf.d/export-file
docker run --name tetragon --rm -d \
  --pid=host --cgroupns=host --privileged \
  -v /etc/tetragon:/etc/tetragon \
  -v /sys/kernel:/sys/kernel \
  -v /var/log/tetragon:/var/log/tetragon \
  quay.io/cilium/tetragon:{{< latest-version >}} \
  /usr/bin/tetragon
{{< /tab >}}
{{< tab systemd >}}
# Change configuration inside /etc/tetragon/ then restart systemd service.
# Example:
#   1. As a privileged user, write to the file /etc/tetragon/tetragon.conf.d/export-file
#      the path where to export events, example "/var/log/tetragon/tetragon.log"
#   2. Bind mount host /etc/tetragon into container /etc/tetragon
# Tetragon events will be exported to /var/log/tetragon/tetragon.log
echo "/var/log/tetragon/tetragon.log" > /etc/tetragon/tetragon.conf.d/export-file
systemctl restart tetragon
{{< /tab >}}
{{< /tabpane >}}

To read more about Tetragon configuration, please check our reference pages:

* For Kubernetes deployments, see the [Helm chart]({{< ref "/docs/reference/helm-chart" >}}) reference.
* For Container or systemd deployments, see the [Daemon configuration]({{< ref "/docs/reference/daemon-configuration" >}})
reference.

## Enable Process Credentials

On Linux each process has various associated user, group IDs and capabilities
known as process credentials. To enable visility into [process_credentials]({{< ref "/docs/reference/grpc-api#processcredentials" >}}),
run Tetragon with `enable-process-creds` setting set.

{{< tabpane lang=shell >}}

{{< tab Kubernetes >}}
kubectl edit cm -n kube-system tetragon-config
# Change "enable-process-cred" from "false" to "true", then save and exit
# Restart Tetragon daemonset
kubectl rollout restart -n kube-system ds/tetragon
{{< /tab >}}
{{< tab Docker >}}
echo "true" > /etc/tetragon/tetragon.conf.d/enable-process-cred
docker run --name tetragon --rm -d \
  --pid=host --cgroupns=host --privileged \
  -v /etc/tetragon:/etc/tetragon \
  -v /sys/kernel:/sys/kernel \
  -v /var/log/tetragon:/var/log/tetragon \
  quay.io/cilium/tetragon:{{< latest-version >}} \
  /usr/bin/tetragon
{{< /tab >}}
{{< tab systemd >}}
# Write to the drop-in file /etc/tetragon/tetragon.conf.d/enable-process-cred  true
# Run the following as a privileged user then restart tetragon service
echo "true" > /etc/tetragon/tetragon.conf.d/enable-process-cred
systemctl restart tetragon
{{< /tab >}}
{{< /tabpane >}}
