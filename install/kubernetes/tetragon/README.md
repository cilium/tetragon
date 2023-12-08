# tetragon

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.0](https://img.shields.io/badge/AppVersion-1.0.0-informational?style=flat-square)

Helm chart for Tetragon

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
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
| tetragon.fieldFilters | string | `"{}"` |  |
| tetragon.gops.address | string | `"localhost"` | The address at which to expose gops. |
| tetragon.gops.port | int | `8118` | The port at which to expose gops. |
| tetragon.grpc.address | string | `"localhost:54321"` | The address at which to expose gRPC. Examples: localhost:54321, unix:///var/run/tetragon/tetragon.sock |
| tetragon.grpc.enabled | bool | `true` | Whether to enable exposing Tetragon gRPC. |
| tetragon.hostProcPath | string | `"/proc"` | Location of the host proc filesystem in the runtime environment. If the runtime runs in the host, the path is /proc. Exceptions to this are environments like kind, where the runtime itself does not run on the host. |
| tetragon.image.override | string | `nil` |  |
| tetragon.image.repository | string | `"quay.io/cilium/tetragon"` |  |
| tetragon.image.tag | string | `"v1.0.0"` |  |
| tetragon.processCacheSize | int | `65536` |  |
| tetragon.prometheus.address | string | `""` | The address at which to expose metrics. Set it to "" to expose on all available interfaces. |
| tetragon.prometheus.enabled | bool | `true` | Whether to enable exposing Tetragon metrics. |
| tetragon.prometheus.metricsLabelFilter | string | `"namespace,workload,pod,binary"` | The labels to include with supporting metrics. The possible values are "namespace", "workload", "pod" and "binary". |
| tetragon.prometheus.port | int | `2112` | The port at which to expose metrics. |
| tetragon.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragon pods. |
| tetragon.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragon.prometheus.serviceMonitor.scrapeInterval | string | `"10s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragon.resources | object | `{}` |  |
| tetragon.securityContext.privileged | bool | `true` |  |
| tetragonOperator | object | `{"affinity":{},"annotations":{},"extraLabels":{},"extraPodLabels":{},"extraVolumeMounts":[],"extraVolumes":[],"image":{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/tetragon-operator","tag":"v1.0.0"},"nodeSelector":{},"podAnnotations":{},"podInfo":{"enabled":false},"podSecurityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},"priorityClassName":"","prometheus":{"address":"","enabled":true,"port":2113,"serviceMonitor":{"enabled":false,"labelsOverride":{},"scrapeInterval":"10s"}},"resources":{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}},"securityContext":{},"serviceAccount":{"annotations":{},"create":true,"name":""},"skipCRDCreation":false,"strategy":{},"tolerations":[{"operator":"Exists"}]}` | Tetragon Operator settings |
| tetragonOperator.annotations | object | `{}` | Annotations for the Tetragon Operator Deployment. |
| tetragonOperator.extraLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment. |
| tetragonOperator.extraPodLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment Pods. |
| tetragonOperator.extraVolumes | list | `[]` | Extra volumes for the Tetragon Operator Deployment. |
| tetragonOperator.image | object | `{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/tetragon-operator","tag":"v1.0.0"}` | tetragon-operator image. |
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
| tolerations[0].operator | string | `"Exists"` |  |
| updateStrategy | object | `{}` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)
