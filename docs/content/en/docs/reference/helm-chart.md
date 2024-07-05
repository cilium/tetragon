---
title: "Helm chart"
description: "This reference is generated from the Tetragon Helm chart values."
weight: 2
---

{{< comment >}}
This page was generated with github.io/cilium/tetragon/install/kubernetes/tetragon/export-doc.sh,
please do not edit directly.
{{< /comment >}}

The Tetragon Helm chart source is available under
[github.io/cilium/tetragon/install/kubernetes/tetragon](https://github.com/cilium/tetragon/tree/main/install/kubernetes/tetragon)
and is distributed from the Cilium helm charts repository [helm.cilium.io](https://helm.cilium.io).

To deploy Tetragon using this Helm chart you can run the following commands:
```shell
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
```

To use [the values available](#values), with `helm install` or `helm upgrade`, use `--set key=value`.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| crds.installMethod | string | `"operator"` | Method for installing CRDs. Supported values are: "operator", "helm" and "none". The "operator" method allows for fine-grained control over which CRDs are installed and by default doesn't perform CRD downgrades. These can be configured in tetragonOperator section. The "helm" method always installs all CRDs for the chart version. |
| daemonSetAnnotations | object | `{}` |  |
| daemonSetLabelsOverride | object | `{}` |  |
| dnsPolicy | string | `"Default"` |  |
| enabled | bool | `true` | Global settings |
| export | object | `{"filenames":["tetragon.log"],"mode":"stdout","resources":{},"securityContext":{},"stdout":{"argsOverride":[],"commandOverride":[],"enabledArgs":true,"enabledCommand":true,"extraEnv":[],"extraVolumeMounts":[],"image":{"override":null,"repository":"quay.io/cilium/hubble-export-stdout","tag":"v1.0.4"}}}` | Tetragon event settings |
| exportDirectory | string | `"/var/run/cilium/tetragon"` |  |
| exportFileCreationInterval | string | `"120s"` |  |
| extraConfigmapMounts | list | `[]` |  |
| extraHostPathMounts | list | `[]` |  |
| extraVolumes | list | `[]` |  |
| hostNetwork | bool | `true` |  |
| imagePullPolicy | string | `"IfNotPresent"` |  |
| imagePullSecrets | list | `[]` |  |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| podLabelsOverride | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| priorityClassName | string | `""` | Tetragon agent settings |
| rthooks | object | `{"annotations":{},"enabled":false,"extraHookArgs":{},"extraLabels":{},"extraVolumeMounts":[],"failAllowNamespaces":"","image":{"override":null,"repository":"quay.io/cilium/tetragon-rthooks","tag":"v0.1"},"installDir":"/opt/tetragon","interface":"","nriHook":{"nriSocket":"/var/run/nri/nri.sock"},"ociHooks":{"hooksPath":"/usr/share/containers/oci/hooks.d"},"podAnnotations":{},"priorityClassName":"","resources":{},"securityContext":{"privileged":true}}` | Method for installing Tetagon rthooks (tetragon-rthooks) daemonset The tetragon-rthooks daemonset is responsible for installing run-time hooks on the host. See: https://tetragon.io/docs/concepts/runtime-hooks |
| rthooks.annotations | object | `{}` | Annotations for the Tetragon rthooks daemonset |
| rthooks.enabled | bool | `false` | Enable the Tetragon rthooks daemonset |
| rthooks.extraHookArgs | object | `{}` | extra args to pass to tetragon-oci-hook |
| rthooks.extraLabels | object | `{}` | Extra labels for the Tetrargon rthooks daemonset |
| rthooks.extraVolumeMounts | list | `[]` | Extra volume mounts to add to the oci-hook-setup init container |
| rthooks.failAllowNamespaces | string | `""` | Comma-separated list of namespaces to allow Pod creation for, in case tetragon-oci-hook fails to reach Tetragon agent. The namespace Tetragon is deployed in is always added as an exception and must not be added again. |
| rthooks.image | object | `{"override":null,"repository":"quay.io/cilium/tetragon-rthooks","tag":"v0.1"}` | image for the Tetragon rthooks pod |
| rthooks.installDir | string | `"/opt/tetragon"` | installDir is the host location where the tetragon-oci-hook binary will be installed |
| rthooks.interface | string | `""` | Method to use for installing  rthooks. Values:     "oci-hooks":       Add an apppriate file to "/usr/share/containers/oci/hooks.d". Use this with CRI-O.       See https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md       for more details.       Specific configuration for this interface can be found under "OciHooks".     "nri-hook":      Install the hook via NRI. Use this with containerd. Requires NRI being enabled.      see: https://github.com/containerd/containerd/blob/main/docs/NRI.md.  |
| rthooks.nriHook | object | `{"nriSocket":"/var/run/nri/nri.sock"}` | configuration for the "nri-hook" interface |
| rthooks.nriHook.nriSocket | string | `"/var/run/nri/nri.sock"` | path to NRI socket |
| rthooks.ociHooks | object | `{"hooksPath":"/usr/share/containers/oci/hooks.d"}` | configuration for "oci-hooks" interface |
| rthooks.ociHooks.hooksPath | string | `"/usr/share/containers/oci/hooks.d"` | directory to install .json file for running the hook |
| rthooks.podAnnotations | object | `{}` | Pod annotations for the Tetrargon rthooks pod |
| rthooks.priorityClassName | string | `""` | priorityClassName for the Tetrargon rthooks pod |
| rthooks.resources | object | `{}` | resources for the the oci-hook-setup init container |
| rthooks.securityContext | object | `{"privileged":true}` | security context for the Tetrargon rthooks pod |
| selectorLabelsOverride | object | `{}` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| serviceLabelsOverride | object | `{}` |  |
| tetragon.argsOverride | list | `[]` |  |
| tetragon.btf | string | `""` |  |
| tetragon.commandOverride | list | `[]` |  |
| tetragon.enableK8sAPI | bool | `true` |  |
| tetragon.enableMsgHandlingLatency | bool | `false` | Enable latency monitoring in message handling |
| tetragon.enablePolicyFilter | bool | `true` | Enable policy filter. This is required for K8s namespace and pod-label filtering. |
| tetragon.enablePolicyFilterDebug | bool | `false` | Enable policy filter debug messages. |
| tetragon.enableProcessCred | bool | `false` |  |
| tetragon.enableProcessNs | bool | `false` |  |
| tetragon.enabled | bool | `true` |  |
| tetragon.exportAllowList | string | `"{\"event_set\":[\"PROCESS_EXEC\", \"PROCESS_EXIT\", \"PROCESS_KPROBE\", \"PROCESS_UPROBE\", \"PROCESS_TRACEPOINT\"]}"` |  |
| tetragon.exportDenyList | string | `"{\"health_check\":true}\n{\"namespace\":[\"\", \"cilium\", \"kube-system\"]}"` |  |
| tetragon.exportFileCompress | bool | `false` |  |
| tetragon.exportFileMaxBackups | int | `5` |  |
| tetragon.exportFileMaxSizeMB | int | `10` |  |
| tetragon.exportFilePerm | string | `"600"` |  |
| tetragon.exportFilename | string | `"tetragon.log"` |  |
| tetragon.exportRateLimit | int | `-1` |  |
| tetragon.extraArgs | object | `{}` |  |
| tetragon.extraEnv | list | `[]` |  |
| tetragon.extraVolumeMounts | list | `[]` |  |
| tetragon.fieldFilters | string | `""` |  |
| tetragon.gops.address | string | `"localhost"` | The address at which to expose gops. |
| tetragon.gops.port | int | `8118` | The port at which to expose gops. |
| tetragon.grpc.address | string | `"localhost:54321"` | The address at which to expose gRPC. Examples: localhost:54321, unix:///var/run/cilum/tetragon/tetragon.sock |
| tetragon.grpc.enabled | bool | `true` | Whether to enable exposing Tetragon gRPC. |
| tetragon.healthGrpc.enabled | bool | `true` | Whether to enable health gRPC server. |
| tetragon.healthGrpc.interval | int | `10` | The interval at which to check the health of the agent. |
| tetragon.healthGrpc.port | int | `6789` | The port at which to expose health gRPC. |
| tetragon.hostProcPath | string | `"/proc"` | Location of the host proc filesystem in the runtime environment. If the runtime runs in the host, the path is /proc. Exceptions to this are environments like kind, where the runtime itself does not run on the host. |
| tetragon.image.override | string | `nil` |  |
| tetragon.image.repository | string | `"quay.io/cilium/tetragon"` |  |
| tetragon.image.tag | string | `"v1.1.2"` |  |
| tetragon.livenessProbe | object | `{}` | Overrides the default livenessProbe for the tetragon container. |
| tetragon.ociHookSetup | object | `{"enabled":false,"extraVolumeMounts":[],"failAllowNamespaces":"","installDir":"/opt/tetragon","interface":"oci-hooks","resources":{},"securityContext":{"privileged":true}}` | Configure tetragon's init container for setting up tetragon-oci-hook on the host NOTE: This is deprecated, please use .rthooks |
| tetragon.ociHookSetup.enabled | bool | `false` | enable  init container to setup tetragon-oci-hook |
| tetragon.ociHookSetup.extraVolumeMounts | list | `[]` | Extra volume mounts to add to the oci-hook-setup init container |
| tetragon.ociHookSetup.failAllowNamespaces | string | `""` | Comma-separated list of namespaces to allow Pod creation for, in case tetragon-oci-hook fails to reach Tetragon agent. The namespace Tetragon is deployed in is always added as an exception and must not be added again. |
| tetragon.ociHookSetup.interface | string | `"oci-hooks"` | interface specifices how the hook is  configured. There is only one avaialble value for now: "oci-hooks" (https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md). |
| tetragon.ociHookSetup.resources | object | `{}` | resources for the the oci-hook-setup init container |
| tetragon.ociHookSetup.securityContext | object | `{"privileged":true}` | Security context for oci-hook-setup init container |
| tetragon.processCacheSize | int | `65536` |  |
| tetragon.prometheus.address | string | `""` | The address at which to expose metrics. Set it to "" to expose on all available interfaces. |
| tetragon.prometheus.enabled | bool | `true` | Whether to enable exposing Tetragon metrics. |
| tetragon.prometheus.metricsLabelFilter | string | `"namespace,workload,pod,binary"` | Comma-separated list of enabled metrics labels. The configurable labels are: namespace, workload, pod, binary. Unkown labels will be ignored. Removing some labels from the list might help reduce the metrics cardinality if needed. |
| tetragon.prometheus.port | int | `2112` | The port at which to expose metrics. |
| tetragon.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragon pods. |
| tetragon.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragon.prometheus.serviceMonitor.scrapeInterval | string | `"10s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragon.redactionFilters | string | `""` |  |
| tetragon.resources | object | `{}` |  |
| tetragon.securityContext.privileged | bool | `true` |  |
| tetragonOperator | object | `{"affinity":{},"annotations":{},"enabled":true,"extraLabels":{},"extraPodLabels":{},"extraVolumeMounts":[],"extraVolumes":[],"forceUpdateCRDs":false,"image":{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/tetragon-operator","tag":"v1.1.2"},"nodeSelector":{},"podAnnotations":{},"podInfo":{"enabled":false},"podSecurityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},"priorityClassName":"","prometheus":{"address":"","enabled":true,"port":2113,"serviceMonitor":{"enabled":false,"labelsOverride":{},"scrapeInterval":"10s"}},"resources":{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}},"securityContext":{},"serviceAccount":{"annotations":{},"create":true,"name":""},"strategy":{},"tolerations":[{"operator":"Exists"}],"tracingPolicy":{"enabled":true}}` | Tetragon Operator settings |
| tetragonOperator.annotations | object | `{}` | Annotations for the Tetragon Operator Deployment. |
| tetragonOperator.enabled | bool | `true` | Enables the Tetragon Operator. |
| tetragonOperator.extraLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment. |
| tetragonOperator.extraPodLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment Pods. |
| tetragonOperator.extraVolumes | list | `[]` | Extra volumes for the Tetragon Operator Deployment. |
| tetragonOperator.image | object | `{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/tetragon-operator","tag":"v1.1.2"}` | tetragon-operator image. |
| tetragonOperator.nodeSelector | object | `{}` | Steer the Tetragon Operator Deployment Pod placement via nodeSelector, tolerations and affinity rules. |
| tetragonOperator.podAnnotations | object | `{}` | Annotations for the Tetragon Operator Deployment Pods. |
| tetragonOperator.podInfo.enabled | bool | `false` | Enables the PodInfo CRD and the controller that reconciles PodInfo custom resources. |
| tetragonOperator.podSecurityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | securityContext for the Tetragon Operator Deployment Pod container. |
| tetragonOperator.priorityClassName | string | `""` | priorityClassName for the Tetragon Operator Deployment Pods. |
| tetragonOperator.prometheus | object | `{"address":"","enabled":true,"port":2113,"serviceMonitor":{"enabled":false,"labelsOverride":{},"scrapeInterval":"10s"}}` | Enables the Tetragon Operator metrics. |
| tetragonOperator.prometheus.address | string | `""` | The address at which to expose Tetragon Operator metrics. Set it to "" to expose on all available interfaces. |
| tetragonOperator.prometheus.port | int | `2113` | The port at which to expose metrics. |
| tetragonOperator.prometheus.serviceMonitor | object | `{"enabled":false,"labelsOverride":{},"scrapeInterval":"10s"}` | The labels to include with supporting metrics. |
| tetragonOperator.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragonOperator pods. |
| tetragonOperator.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragonOperator.prometheus.serviceMonitor.scrapeInterval | string | `"10s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragonOperator.resources | object | `{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}` | resources for the Tetragon Operator Deployment Pod container. |
| tetragonOperator.securityContext | object | `{}` | securityContext for the Tetragon Operator Deployment Pods. |
| tetragonOperator.serviceAccount | object | `{"annotations":{},"create":true,"name":""}` | tetragon-operator service account. |
| tetragonOperator.strategy | object | `{}` | resources for the Tetragon Operator Deployment update strategy |
| tetragonOperator.tracingPolicy.enabled | bool | `true` | Enables the TracingPolicy and TracingPolicyNamespaced CRD creation. |
| tolerations[0].operator | string | `"Exists"` |  |
| updateStrategy | object | `{}` |  |
