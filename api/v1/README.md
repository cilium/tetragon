# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [tetragon/capabilities.proto](#tetragon_capabilities-proto)
    - [CapabilitiesType](#tetragon-CapabilitiesType)
  
- [tetragon/tetragon.proto](#tetragon_tetragon-proto)
    - [Capabilities](#tetragon-Capabilities)
    - [Container](#tetragon-Container)
    - [GetHealthStatusRequest](#tetragon-GetHealthStatusRequest)
    - [GetHealthStatusResponse](#tetragon-GetHealthStatusResponse)
    - [HealthStatus](#tetragon-HealthStatus)
    - [Image](#tetragon-Image)
    - [KprobeArgument](#tetragon-KprobeArgument)
    - [KprobeBpfAttr](#tetragon-KprobeBpfAttr)
    - [KprobeBpfMap](#tetragon-KprobeBpfMap)
    - [KprobeCapability](#tetragon-KprobeCapability)
    - [KprobeCred](#tetragon-KprobeCred)
    - [KprobeFile](#tetragon-KprobeFile)
    - [KprobePath](#tetragon-KprobePath)
    - [KprobePerfEvent](#tetragon-KprobePerfEvent)
    - [KprobeSkb](#tetragon-KprobeSkb)
    - [KprobeSock](#tetragon-KprobeSock)
    - [KprobeTruncatedBytes](#tetragon-KprobeTruncatedBytes)
    - [KprobeUserNamespace](#tetragon-KprobeUserNamespace)
    - [Namespace](#tetragon-Namespace)
    - [Namespaces](#tetragon-Namespaces)
    - [Pod](#tetragon-Pod)
    - [Pod.PodLabelsEntry](#tetragon-Pod-PodLabelsEntry)
    - [Process](#tetragon-Process)
    - [ProcessExec](#tetragon-ProcessExec)
    - [ProcessExit](#tetragon-ProcessExit)
    - [ProcessKprobe](#tetragon-ProcessKprobe)
    - [ProcessTracepoint](#tetragon-ProcessTracepoint)
    - [Test](#tetragon-Test)
  
    - [HealthStatusResult](#tetragon-HealthStatusResult)
    - [HealthStatusType](#tetragon-HealthStatusType)
    - [KprobeAction](#tetragon-KprobeAction)
  
- [tetragon/events.proto](#tetragon_events-proto)
    - [AggregationInfo](#tetragon-AggregationInfo)
    - [AggregationOptions](#tetragon-AggregationOptions)
    - [FieldFilter](#tetragon-FieldFilter)
    - [Filter](#tetragon-Filter)
    - [GetEventsRequest](#tetragon-GetEventsRequest)
    - [GetEventsResponse](#tetragon-GetEventsResponse)
  
    - [EventType](#tetragon-EventType)
    - [FieldFilterAction](#tetragon-FieldFilterAction)
  
- [tetragon/stack.proto](#tetragon_stack-proto)
    - [StackAddress](#tetragon-StackAddress)
    - [StackTrace](#tetragon-StackTrace)
    - [StackTraceLabel](#tetragon-StackTraceLabel)
    - [StackTraceNode](#tetragon-StackTraceNode)
  
- [tetragon/sensors.proto](#tetragon_sensors-proto)
    - [AddTracingPolicyRequest](#tetragon-AddTracingPolicyRequest)
    - [AddTracingPolicyResponse](#tetragon-AddTracingPolicyResponse)
    - [DeleteTracingPolicyRequest](#tetragon-DeleteTracingPolicyRequest)
    - [DeleteTracingPolicyResponse](#tetragon-DeleteTracingPolicyResponse)
    - [DisableSensorRequest](#tetragon-DisableSensorRequest)
    - [DisableSensorResponse](#tetragon-DisableSensorResponse)
    - [EnableSensorRequest](#tetragon-EnableSensorRequest)
    - [EnableSensorResponse](#tetragon-EnableSensorResponse)
    - [GetSensorConfigRequest](#tetragon-GetSensorConfigRequest)
    - [GetSensorConfigResponse](#tetragon-GetSensorConfigResponse)
    - [GetStackTraceTreeRequest](#tetragon-GetStackTraceTreeRequest)
    - [GetStackTraceTreeResponse](#tetragon-GetStackTraceTreeResponse)
    - [GetVersionRequest](#tetragon-GetVersionRequest)
    - [GetVersionResponse](#tetragon-GetVersionResponse)
    - [ListSensorsRequest](#tetragon-ListSensorsRequest)
    - [ListSensorsResponse](#tetragon-ListSensorsResponse)
    - [RemoveSensorRequest](#tetragon-RemoveSensorRequest)
    - [RemoveSensorResponse](#tetragon-RemoveSensorResponse)
    - [SensorStatus](#tetragon-SensorStatus)
    - [SetSensorConfigRequest](#tetragon-SetSensorConfigRequest)
    - [SetSensorConfigResponse](#tetragon-SetSensorConfigResponse)
  
    - [FineGuidanceSensors](#tetragon-FineGuidanceSensors)
  
- [Scalar Value Types](#scalar-value-types)



<a name="tetragon_capabilities-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/capabilities.proto


 


<a name="tetragon-CapabilitiesType"></a>

### CapabilitiesType


| Name | Number | Description |
| ---- | ------ | ----------- |
| CAP_CHOWN | 0 | In a system with the [_POSIX_CHOWN_RESTRICTED] option defined, this overrides the restriction of changing file ownership and group ownership. |
| DAC_OVERRIDE | 1 | Override all DAC access, including ACL execute access if [_POSIX_ACL] is defined. Excluding DAC access covered by CAP_LINUX_IMMUTABLE. |
| CAP_DAC_READ_SEARCH | 2 | Overrides all DAC restrictions regarding read and search on files and directories, including ACL restrictions if [_POSIX_ACL] is defined. Excluding DAC access covered by &#34;$1&#34;_LINUX_IMMUTABLE. |
| CAP_FOWNER | 3 | Overrides all restrictions about allowed operations on files, where file owner ID must be equal to the user ID, except where CAP_FSETID is applicable. It doesn&#39;t override MAC and DAC restrictions. |
| CAP_FSETID | 4 | Overrides the following restrictions that the effective user ID shall match the file owner ID when setting the S_ISUID and S_ISGID bits on that file; that the effective group ID (or one of the supplementary group IDs) shall match the file owner ID when setting the S_ISGID bit on that file; that the S_ISUID and S_ISGID bits are cleared on successful return from chown(2) (not implemented). |
| CAP_KILL | 5 | Overrides the restriction that the real or effective user ID of a process sending a signal must match the real or effective user ID of the process receiving the signal. |
| CAP_SETGID | 6 | Allows forged gids on socket credentials passing. |
| CAP_SETUID | 7 | Allows forged pids on socket credentials passing. |
| CAP_SETPCAP | 8 | Without VFS support for capabilities: Transfer any capability in your permitted set to any pid, remove any capability in your permitted set from any pid With VFS support for capabilities (neither of above, but) Add any capability from current&#39;s capability bounding set to the current process&#39; inheritable set Allow taking bits out of capability bounding set Allow modification of the securebits for a process |
| CAP_LINUX_IMMUTABLE | 9 | Allow modification of S_IMMUTABLE and S_APPEND file attributes |
| CAP_NET_BIND_SERVICE | 10 | Allows binding to ATM VCIs below 32 |
| CAP_NET_BROADCAST | 11 | Allow broadcasting, listen to multicast |
| CAP_NET_ADMIN | 12 | Allow activation of ATM control sockets |
| CAP_NET_RAW | 13 | Allow binding to any address for transparent proxying (also via NET_ADMIN) |
| CAP_IPC_LOCK | 14 | Allow mlock and mlockall (which doesn&#39;t really have anything to do with IPC) |
| CAP_IPC_OWNER | 15 | Override IPC ownership checks |
| CAP_SYS_MODULE | 16 | Insert and remove kernel modules - modify kernel without limit |
| CAP_SYS_RAWIO | 17 | Allow sending USB messages to any device via /dev/bus/usb |
| CAP_SYS_CHROOT | 18 | Allow use of chroot() |
| CAP_SYS_PTRACE | 19 | Allow ptrace() of any process |
| CAP_SYS_PACCT | 20 | Allow configuration of process accounting |
| CAP_SYS_ADMIN | 21 | Allow everything under CAP_BPF and CAP_PERFMON for backward compatibility |
| CAP_SYS_BOOT | 22 | Allow use of reboot() |
| CAP_SYS_NICE | 23 | Allow setting cpu affinity on other processes |
| CAP_SYS_RESOURCE | 24 | Control memory reclaim behavior |
| CAP_SYS_TIME | 25 | Allow setting the real-time clock |
| CAP_SYS_TTY_CONFIG | 26 | Allow vhangup() of tty |
| CAP_MKNOD | 27 | Allow the privileged aspects of mknod() |
| CAP_LEASE | 28 | Allow taking of leases on files |
| CAP_AUDIT_WRITE | 29 | Allow writing the audit log via unicast netlink socket |
| CAP_AUDIT_CONTROL | 30 | Allow configuration of audit via unicast netlink socket |
| CAP_SETFCAP | 31 | Set or remove capabilities on files |
| CAP_MAC_OVERRIDE | 32 | Override MAC access. The base kernel enforces no MAC policy. An LSM may enforce a MAC policy, and if it does and it chooses to implement capability based overrides of that policy, this is the capability it should use to do so. |
| CAP_MAC_ADMIN | 33 | Allow MAC configuration or state changes. The base kernel requires no MAC configuration. An LSM may enforce a MAC policy, and if it does and it chooses to implement capability based checks on modifications to that policy or the data required to maintain it, this is the capability it should use to do so. |
| CAP_SYSLOG | 34 | Allow configuring the kernel&#39;s syslog (printk behaviour) |
| CAP_WAKE_ALARM | 35 | Allow triggering something that will wake the system |
| CAP_BLOCK_SUSPEND | 36 | Allow preventing system suspends |
| CAP_AUDIT_READ | 37 | Allow reading the audit log via multicast netlink socket |
| CAP_PERFMON | 38 | Allow system performance and observability privileged operations using perf_events, i915_perf and other kernel subsystems |
| CAP_BPF | 39 | CAP_BPF allows the following BPF operations: - Creating all types of BPF maps - Advanced verifier features - Indirect variable access - Bounded loops - BPF to BPF function calls - Scalar precision tracking - Larger complexity limits - Dead code elimination - And potentially other features - Loading BPF Type Format (BTF) data - Retrieve xlated and JITed code of BPF programs - Use bpf_spin_lock() helper CAP_PERFMON relaxes the verifier checks further: - BPF progs can use of pointer-to-integer conversions - speculation attack hardening measures are bypassed - bpf_probe_read to read arbitrary kernel memory is allowed - bpf_trace_printk to print kernel memory is allowed CAP_SYS_ADMIN is required to use bpf_probe_write_user. CAP_SYS_ADMIN is required to iterate system wide loaded programs, maps, links, BTFs and convert their IDs to file descriptors. CAP_PERFMON and CAP_BPF are required to load tracing programs. CAP_NET_ADMIN and CAP_BPF are required to load networking programs. |
| CAP_CHECKPOINT_RESTORE | 40 | Allow writing to ns_last_pid |


 

 

 



<a name="tetragon_tetragon-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/tetragon.proto



<a name="tetragon-Capabilities"></a>

### Capabilities



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| permitted | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated |  |
| effective | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated |  |
| inheritable | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated |  |






<a name="tetragon-Container"></a>

### Container



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| name | [string](#string) |  |  |
| image | [Image](#tetragon-Image) |  |  |
| start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Start time of the container. |
| pid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | PID in the container namespace. |
| maybe_exec_probe | [bool](#bool) |  | If this is set true, it means that the process might have been originated from a Kubernetes exec probe. For this field to be true, the following must be true: 1. The binary field matches the first element of the exec command list for either liveness or readiness probe excluding the basename. For example, &#34;/bin/ls&#34; and &#34;ls&#34; are considered a match. 2. The arguments field exactly matches the rest of the exec command list. |






<a name="tetragon-GetHealthStatusRequest"></a>

### GetHealthStatusRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event_set | [HealthStatusType](#tetragon-HealthStatusType) | repeated |  |






<a name="tetragon-GetHealthStatusResponse"></a>

### GetHealthStatusResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| health_status | [HealthStatus](#tetragon-HealthStatus) | repeated |  |






<a name="tetragon-HealthStatus"></a>

### HealthStatus



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event | [HealthStatusType](#tetragon-HealthStatusType) |  |  |
| status | [HealthStatusResult](#tetragon-HealthStatusResult) |  |  |
| details | [string](#string) |  |  |






<a name="tetragon-Image"></a>

### Image



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| name | [string](#string) |  |  |






<a name="tetragon-KprobeArgument"></a>

### KprobeArgument



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| string_arg | [string](#string) |  |  |
| int_arg | [int32](#int32) |  |  |
| skb_arg | [KprobeSkb](#tetragon-KprobeSkb) |  |  |
| size_arg | [uint64](#uint64) |  |  |
| bytes_arg | [bytes](#bytes) |  |  |
| path_arg | [KprobePath](#tetragon-KprobePath) |  |  |
| file_arg | [KprobeFile](#tetragon-KprobeFile) |  |  |
| truncated_bytes_arg | [KprobeTruncatedBytes](#tetragon-KprobeTruncatedBytes) |  |  |
| sock_arg | [KprobeSock](#tetragon-KprobeSock) |  |  |
| cred_arg | [KprobeCred](#tetragon-KprobeCred) |  |  |
| long_arg | [int64](#int64) |  |  |
| bpf_attr_arg | [KprobeBpfAttr](#tetragon-KprobeBpfAttr) |  |  |
| perf_event_arg | [KprobePerfEvent](#tetragon-KprobePerfEvent) |  |  |
| bpf_map_arg | [KprobeBpfMap](#tetragon-KprobeBpfMap) |  |  |
| uint_arg | [uint32](#uint32) |  |  |
| user_namespace_arg | [KprobeUserNamespace](#tetragon-KprobeUserNamespace) |  |  |
| capability_arg | [KprobeCapability](#tetragon-KprobeCapability) |  |  |






<a name="tetragon-KprobeBpfAttr"></a>

### KprobeBpfAttr



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ProgType | [string](#string) |  |  |
| InsnCnt | [uint32](#uint32) |  |  |
| ProgName | [string](#string) |  |  |






<a name="tetragon-KprobeBpfMap"></a>

### KprobeBpfMap



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| MapType | [string](#string) |  |  |
| KeySize | [uint32](#uint32) |  |  |
| ValueSize | [uint32](#uint32) |  |  |
| MaxEntries | [uint32](#uint32) |  |  |
| MapName | [string](#string) |  |  |






<a name="tetragon-KprobeCapability"></a>

### KprobeCapability



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [google.protobuf.Int32Value](#google-protobuf-Int32Value) |  |  |
| name | [string](#string) |  |  |






<a name="tetragon-KprobeCred"></a>

### KprobeCred



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| permitted | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated |  |
| effective | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated |  |
| inheritable | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated |  |






<a name="tetragon-KprobeFile"></a>

### KprobeFile



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| mount | [string](#string) |  |  |
| path | [string](#string) |  |  |
| flags | [string](#string) |  |  |






<a name="tetragon-KprobePath"></a>

### KprobePath



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| mount | [string](#string) |  |  |
| path | [string](#string) |  |  |
| flags | [string](#string) |  |  |






<a name="tetragon-KprobePerfEvent"></a>

### KprobePerfEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| KprobeFunc | [string](#string) |  |  |
| Type | [string](#string) |  |  |
| Config | [uint64](#uint64) |  |  |
| ProbeOffset | [uint64](#uint64) |  |  |






<a name="tetragon-KprobeSkb"></a>

### KprobeSkb



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hash | [uint32](#uint32) |  |  |
| len | [uint32](#uint32) |  |  |
| priority | [uint32](#uint32) |  |  |
| mark | [uint32](#uint32) |  |  |
| saddr | [string](#string) |  |  |
| daddr | [string](#string) |  |  |
| sport | [uint32](#uint32) |  |  |
| dport | [uint32](#uint32) |  |  |
| proto | [uint32](#uint32) |  |  |
| sec_path_len | [uint32](#uint32) |  |  |
| sec_path_olen | [uint32](#uint32) |  |  |






<a name="tetragon-KprobeSock"></a>

### KprobeSock



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| family | [string](#string) |  |  |
| type | [string](#string) |  |  |
| protocol | [string](#string) |  |  |
| mark | [uint32](#uint32) |  |  |
| priority | [uint32](#uint32) |  |  |
| saddr | [string](#string) |  |  |
| daddr | [string](#string) |  |  |
| sport | [uint32](#uint32) |  |  |
| dport | [uint32](#uint32) |  |  |






<a name="tetragon-KprobeTruncatedBytes"></a>

### KprobeTruncatedBytes



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bytes_arg | [bytes](#bytes) |  |  |
| orig_size | [uint64](#uint64) |  |  |






<a name="tetragon-KprobeUserNamespace"></a>

### KprobeUserNamespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| level | [google.protobuf.Int32Value](#google-protobuf-Int32Value) |  |  |
| owner | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| group | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| ns | [Namespace](#tetragon-Namespace) |  |  |






<a name="tetragon-Namespace"></a>

### Namespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inum | [uint32](#uint32) |  |  |
| is_host | [bool](#bool) |  |  |






<a name="tetragon-Namespaces"></a>

### Namespaces



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uts | [Namespace](#tetragon-Namespace) |  |  |
| ipc | [Namespace](#tetragon-Namespace) |  |  |
| mnt | [Namespace](#tetragon-Namespace) |  |  |
| pid | [Namespace](#tetragon-Namespace) |  |  |
| pid_for_children | [Namespace](#tetragon-Namespace) |  |  |
| net | [Namespace](#tetragon-Namespace) |  |  |
| time | [Namespace](#tetragon-Namespace) |  |  |
| time_for_children | [Namespace](#tetragon-Namespace) |  |  |
| cgroup | [Namespace](#tetragon-Namespace) |  |  |
| user | [Namespace](#tetragon-Namespace) |  |  |






<a name="tetragon-Pod"></a>

### Pod



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  |  |
| name | [string](#string) |  |  |
| labels | [string](#string) | repeated |  |
| container | [Container](#tetragon-Container) |  |  |
| pod_labels | [Pod.PodLabelsEntry](#tetragon-Pod-PodLabelsEntry) | repeated | pod_labels field contains all the labels of the pod. Note that the labels field contains Cilium identity labels, which is a subset of pod labels. |






<a name="tetragon-Pod-PodLabelsEntry"></a>

### Pod.PodLabelsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="tetragon-Process"></a>

### Process



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| exec_id | [string](#string) |  | Exec ID uniquely identifies the process over time across all the nodes in the cluster. |
| pid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| uid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| cwd | [string](#string) |  |  |
| binary | [string](#string) |  |  |
| arguments | [string](#string) |  |  |
| flags | [string](#string) |  |  |
| start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| auid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| pod | [Pod](#tetragon-Pod) |  |  |
| docker | [string](#string) |  |  |
| parent_exec_id | [string](#string) |  |  |
| refcnt | [uint32](#uint32) |  |  |
| cap | [Capabilities](#tetragon-Capabilities) |  |  |
| ns | [Namespaces](#tetragon-Namespaces) |  |  |
| dest_pod | [Pod](#tetragon-Pod) |  |  |






<a name="tetragon-ProcessExec"></a>

### ProcessExec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| parent | [Process](#tetragon-Process) |  |  |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |






<a name="tetragon-ProcessExit"></a>

### ProcessExit



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| parent | [Process](#tetragon-Process) |  |  |
| signal | [string](#string) |  |  |
| status | [uint32](#uint32) |  |  |






<a name="tetragon-ProcessKprobe"></a>

### ProcessKprobe



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| parent | [Process](#tetragon-Process) |  |  |
| function_name | [string](#string) |  |  |
| args | [KprobeArgument](#tetragon-KprobeArgument) | repeated |  |
| return | [KprobeArgument](#tetragon-KprobeArgument) |  |  |
| action | [KprobeAction](#tetragon-KprobeAction) |  |  |






<a name="tetragon-ProcessTracepoint"></a>

### ProcessTracepoint



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| parent | [Process](#tetragon-Process) |  |  |
| subsys | [string](#string) |  |  |
| event | [string](#string) |  |  |
| args | [KprobeArgument](#tetragon-KprobeArgument) | repeated | TODO: once we implement all we want, rename KprobeArgument to GenericArgument |






<a name="tetragon-Test"></a>

### Test



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| arg0 | [uint64](#uint64) |  |  |
| arg1 | [uint64](#uint64) |  |  |
| arg2 | [uint64](#uint64) |  |  |
| arg3 | [uint64](#uint64) |  |  |





 


<a name="tetragon-HealthStatusResult"></a>

### HealthStatusResult


| Name | Number | Description |
| ---- | ------ | ----------- |
| HEALTH_STATUS_UNDEF | 0 |  |
| HEALTH_STATUS_RUNNING | 1 |  |
| HEALTH_STATUS_STOPPED | 2 |  |
| HEALTH_STATUS_ERROR | 3 |  |



<a name="tetragon-HealthStatusType"></a>

### HealthStatusType


| Name | Number | Description |
| ---- | ------ | ----------- |
| HEALTH_STATUS_TYPE_UNDEF | 0 |  |
| HEALTH_STATUS_TYPE_STATUS | 1 |  |



<a name="tetragon-KprobeAction"></a>

### KprobeAction


| Name | Number | Description |
| ---- | ------ | ----------- |
| KPROBE_ACTION_UNKNOWN | 0 |  |
| KPROBE_ACTION_POST | 1 |  |
| KPROBE_ACTION_FOLLOWFD | 2 |  |
| KPROBE_ACTION_SIGKILL | 3 |  |
| KPROBE_ACTION_UNFOLLOWFD | 4 |  |
| KPROBE_ACTION_OVERRIDE | 5 |  |
| KPROBE_ACTION_COPYFD | 6 |  |
| KPROBE_ACTION_GETURL | 7 |  |
| KPROBE_ACTION_DNSLOOKUP | 8 |  |


 

 

 



<a name="tetragon_events-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/events.proto



<a name="tetragon-AggregationInfo"></a>

### AggregationInfo
AggregationInfo contains information about aggregation results.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| count | [uint64](#uint64) |  | Total count of events in this aggregation time window. |






<a name="tetragon-AggregationOptions"></a>

### AggregationOptions
AggregationOptions defines configuration options for aggregating events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| window_size | [google.protobuf.Duration](#google-protobuf-Duration) |  | Aggregation window size. Defaults to 15 seconds if this field is not set. |
| channel_buffer_size | [uint64](#uint64) |  | Size of the buffer for the aggregator to receive incoming events. If the buffer becomes full, the aggregator will log a warning and start dropping incoming events. |






<a name="tetragon-FieldFilter"></a>

### FieldFilter



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event_set | [EventType](#tetragon-EventType) | repeated | Event types to filter or undefined to filter over all event types. |
| fields | [google.protobuf.FieldMask](#google-protobuf-FieldMask) |  | Fields to include or exclude. |
| action | [FieldFilterAction](#tetragon-FieldFilterAction) |  | Whether to include or exclude fields. |
| invert_event_set | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  | Whether or not the event set filter should be inverted. |






<a name="tetragon-Filter"></a>

### Filter



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| binary_regex | [string](#string) | repeated |  |
| namespace | [string](#string) | repeated |  |
| health_check | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  |  |
| pid | [uint32](#uint32) | repeated |  |
| pid_set | [uint32](#uint32) | repeated |  |
| event_set | [EventType](#tetragon-EventType) | repeated |  |
| pod_regex | [string](#string) | repeated | Filter by process.pod.name field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| arguments_regex | [string](#string) | repeated | Filter by process.arguments field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| labels | [string](#string) | repeated | Filter events by pod labels using Kubernetes label selector syntax: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors Note that this filter never matches events without the pod field (i.e. host process events). |






<a name="tetragon-GetEventsRequest"></a>

### GetEventsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allow_list | [Filter](#tetragon-Filter) | repeated | allow_list specifies a list of filters to apply to only return certain events. If multiple filters are specified, at least one of them has to match for an event to be included in the results. |
| deny_list | [Filter](#tetragon-Filter) | repeated | deny_list specifies a list of filters to apply to exclude certain events from the results. If multiple filters are specified, at least one of them has to match for an event to be excluded.

If both allow_list and deny_list are specified, the results contain the set difference allow_list - deny_list. |
| aggregation_options | [AggregationOptions](#tetragon-AggregationOptions) |  | aggregation_options configures aggregation options for this request. If this field is not set, responses will not be aggregated.

Note that currently only process_accept and process_connect events are aggregated. Other events remain unaggregated. |
| field_filters | [FieldFilter](#tetragon-FieldFilter) | repeated | Fields to include or exclude for events in the GetEventsResponse. Omitting this field implies that all fields will be included. Exclusion always takes precedence over inclusion in the case of conflicts. |






<a name="tetragon-GetEventsResponse"></a>

### GetEventsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process_exec | [ProcessExec](#tetragon-ProcessExec) |  |  |
| process_exit | [ProcessExit](#tetragon-ProcessExit) |  |  |
| process_kprobe | [ProcessKprobe](#tetragon-ProcessKprobe) |  |  |
| process_tracepoint | [ProcessTracepoint](#tetragon-ProcessTracepoint) |  |  |
| test | [Test](#tetragon-Test) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed.

For an aggregated response, this field to set to the timestamp at which the event was observed for the first time in a given aggregation time window. |
| aggregation_info | [AggregationInfo](#tetragon-AggregationInfo) |  | aggregation_info contains information about aggregation results. This field is set only for aggregated responses. |





 


<a name="tetragon-EventType"></a>

### EventType
Represents the type of a Tetragon event.

NOTE: EventType constants must be in sync with the numbers used in the
GetEventsResponse event oneof.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNDEF | 0 |  |
| PROCESS_EXEC | 1 |  |
| PROCESS_EXIT | 5 |  |
| PROCESS_KPROBE | 9 |  |
| PROCESS_TRACEPOINT | 10 |  |
| TEST | 40000 |  |



<a name="tetragon-FieldFilterAction"></a>

### FieldFilterAction
Determins the behaviour of a field filter

| Name | Number | Description |
| ---- | ------ | ----------- |
| INCLUDE | 0 |  |
| EXCLUDE | 1 |  |


 

 

 



<a name="tetragon_stack-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/stack.proto



<a name="tetragon-StackAddress"></a>

### StackAddress



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [uint64](#uint64) |  |  |
| symbol | [string](#string) |  |  |






<a name="tetragon-StackTrace"></a>

### StackTrace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| addresses | [StackAddress](#tetragon-StackAddress) | repeated |  |






<a name="tetragon-StackTraceLabel"></a>

### StackTraceLabel



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| count | [uint64](#uint64) |  |  |






<a name="tetragon-StackTraceNode"></a>

### StackTraceNode



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [StackAddress](#tetragon-StackAddress) |  |  |
| count | [uint64](#uint64) |  |  |
| labels | [StackTraceLabel](#tetragon-StackTraceLabel) | repeated |  |
| children | [StackTraceNode](#tetragon-StackTraceNode) | repeated |  |





 

 

 

 



<a name="tetragon_sensors-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/sensors.proto



<a name="tetragon-AddTracingPolicyRequest"></a>

### AddTracingPolicyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| yaml | [string](#string) |  |  |






<a name="tetragon-AddTracingPolicyResponse"></a>

### AddTracingPolicyResponse







<a name="tetragon-DeleteTracingPolicyRequest"></a>

### DeleteTracingPolicyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| yaml | [string](#string) |  |  |






<a name="tetragon-DeleteTracingPolicyResponse"></a>

### DeleteTracingPolicyResponse







<a name="tetragon-DisableSensorRequest"></a>

### DisableSensorRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon-DisableSensorResponse"></a>

### DisableSensorResponse







<a name="tetragon-EnableSensorRequest"></a>

### EnableSensorRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon-EnableSensorResponse"></a>

### EnableSensorResponse







<a name="tetragon-GetSensorConfigRequest"></a>

### GetSensorConfigRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| cfgkey | [string](#string) |  |  |






<a name="tetragon-GetSensorConfigResponse"></a>

### GetSensorConfigResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cfgval | [string](#string) |  |  |






<a name="tetragon-GetStackTraceTreeRequest"></a>

### GetStackTraceTreeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon-GetStackTraceTreeResponse"></a>

### GetStackTraceTreeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| root | [StackTraceNode](#tetragon-StackTraceNode) |  |  |






<a name="tetragon-GetVersionRequest"></a>

### GetVersionRequest







<a name="tetragon-GetVersionResponse"></a>

### GetVersionResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| version | [string](#string) |  |  |






<a name="tetragon-ListSensorsRequest"></a>

### ListSensorsRequest







<a name="tetragon-ListSensorsResponse"></a>

### ListSensorsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| sensors | [SensorStatus](#tetragon-SensorStatus) | repeated |  |






<a name="tetragon-RemoveSensorRequest"></a>

### RemoveSensorRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon-RemoveSensorResponse"></a>

### RemoveSensorResponse







<a name="tetragon-SensorStatus"></a>

### SensorStatus



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| enabled | [bool](#bool) |  |  |






<a name="tetragon-SetSensorConfigRequest"></a>

### SetSensorConfigRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| cfgkey | [string](#string) |  |  |
| cfgval | [string](#string) |  |  |






<a name="tetragon-SetSensorConfigResponse"></a>

### SetSensorConfigResponse






 

 

 


<a name="tetragon-FineGuidanceSensors"></a>

### FineGuidanceSensors


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetEvents | [GetEventsRequest](#tetragon-GetEventsRequest) | [GetEventsResponse](#tetragon-GetEventsResponse) stream |  |
| GetHealth | [GetHealthStatusRequest](#tetragon-GetHealthStatusRequest) | [GetHealthStatusResponse](#tetragon-GetHealthStatusResponse) |  |
| AddTracingPolicy | [AddTracingPolicyRequest](#tetragon-AddTracingPolicyRequest) | [AddTracingPolicyResponse](#tetragon-AddTracingPolicyResponse) |  |
| RemoveSensor | [RemoveSensorRequest](#tetragon-RemoveSensorRequest) | [RemoveSensorResponse](#tetragon-RemoveSensorResponse) |  |
| ListSensors | [ListSensorsRequest](#tetragon-ListSensorsRequest) | [ListSensorsResponse](#tetragon-ListSensorsResponse) |  |
| EnableSensor | [EnableSensorRequest](#tetragon-EnableSensorRequest) | [EnableSensorResponse](#tetragon-EnableSensorResponse) |  |
| DisableSensor | [DisableSensorRequest](#tetragon-DisableSensorRequest) | [DisableSensorResponse](#tetragon-DisableSensorResponse) |  |
| SetSensorConfig | [SetSensorConfigRequest](#tetragon-SetSensorConfigRequest) | [SetSensorConfigResponse](#tetragon-SetSensorConfigResponse) |  |
| GetSensorConfig | [GetSensorConfigRequest](#tetragon-GetSensorConfigRequest) | [GetSensorConfigResponse](#tetragon-GetSensorConfigResponse) |  |
| GetStackTraceTree | [GetStackTraceTreeRequest](#tetragon-GetStackTraceTreeRequest) | [GetStackTraceTreeResponse](#tetragon-GetStackTraceTreeResponse) |  |
| GetVersion | [GetVersionRequest](#tetragon-GetVersionRequest) | [GetVersionResponse](#tetragon-GetVersionResponse) |  |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

