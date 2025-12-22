---
title: "gRPC API"
description: >
  This reference is generated from the protocol buffer specification and
  documents the gRPC API of Tetragon.
weight: 3
---

{{< comment >}}
This page was generated with github.io/cilium/tetragon/api/export-doc.sh,
please do not edit directly.
{{< /comment >}}

The Tetragon API is an independant Go module that can be found in the Tetragon
repository under [api](https://github.com/cilium/tetragon/tree/main/api). The
version 1 of this API is defined in
[github.com/cilium/tetragon/api/v1/tetragon](https://github.com/cilium/tetragon/tree/main/api/v1/tetragon).

## tetragon/bpf.proto

<a name="tetragon-BpfCmd"></a>

### BpfCmd

| Name | Number | Description |
| ---- | ------ | ----------- |
| BPF_MAP_CREATE | 0 | Create a map and return a file descriptor that refers to the map. |
| BPF_MAP_LOOKUP_ELEM | 1 | Look up an element with a given key in the map referred to by the file descriptor map_fd. |
| BPF_MAP_UPDATE_ELEM | 2 | Create or update an element (key/value pair) in a specified map. |
| BPF_MAP_DELETE_ELEM | 3 | Look up and delete an element by key in a specified map. |
| BPF_MAP_GET_NEXT_KEY | 4 | Look up an element by key in a specified map and return the key of the next element. Can be used to iterate over all elements in the map. |
| BPF_PROG_LOAD | 5 | Verify and load an eBPF program, returning a new file descriptor associated with the program. |
| BPF_OBJ_PIN | 6 | Pin an eBPF program or map referred by the specified bpf_fd to the provided pathname on the filesystem. |
| BPF_OBJ_GET | 7 | Open a file descriptor for the eBPF object pinned to the specified pathname. |
| BPF_PROG_ATTACH | 8 | Attach an eBPF program to a target_fd at the specified attach_type hook. |
| BPF_PROG_DETACH | 9 | Detach the eBPF program associated with the target_fd at the hook specified by attach_type. |
| BPF_PROG_TEST_RUN | 10 | Run the eBPF program associated with the prog_fd a repeat number of times against a provided program context ctx_in and data data_in, and return the modified program context ctx_out, data_out (for example, packet data), result of the execution retval, and duration of the test run. |
| BPF_PROG_GET_NEXT_ID | 11 | Fetch the next eBPF program currently loaded into the kernel. |
| BPF_MAP_GET_NEXT_ID | 12 | Fetch the next eBPF map currently loaded into the kernel. |
| BPF_PROG_GET_FD_BY_ID | 13 | Open a file descriptor for the eBPF program corresponding to prog_id. |
| BPF_MAP_GET_FD_BY_ID | 14 | Open a file descriptor for the eBPF map corresponding to map_id. |
| BPF_OBJ_GET_INFO_BY_FD | 15 | Obtain information about the eBPF object corresponding to bpf_fd. |
| BPF_PROG_QUERY | 16 | Obtain information about eBPF programs associated with the specified attach_type hook. |
| BPF_RAW_TRACEPOINT_OPEN | 17 | Attach an eBPF program to a tracepoint *name* to access kernel internal arguments of the tracepoint in their raw form. |
| BPF_BTF_LOAD | 18 | Verify and load BPF Type Format (BTF) metadata into the kernel, returning a new file descriptor associated with the metadata. |
| BPF_BTF_GET_FD_BY_ID | 19 | Open a file descriptor for the BPF Type Format (BTF) corresponding to btf_id. |
| BPF_TASK_FD_QUERY | 20 | Obtain information about eBPF programs associated with the target process identified by pid and fd. |
| BPF_MAP_LOOKUP_AND_DELETE_ELEM | 21 | Look up an element with the given key in the map referred to by the file descriptor fd, and if found, delete the element. |
| BPF_MAP_FREEZE | 22 | Freeze the permissions of the specified map. |
| BPF_BTF_GET_NEXT_ID | 23 | Fetch the next BPF Type Format (BTF) object currently loaded into the kernel. |
| BPF_MAP_LOOKUP_BATCH | 24 | Iterate and fetch multiple elements in a map. |
| BPF_MAP_LOOKUP_AND_DELETE_BATCH | 25 | Iterate and delete all elements in a map. |
| BPF_MAP_UPDATE_BATCH | 26 | Update multiple elements in a map by key. |
| BPF_MAP_DELETE_BATCH | 27 | Delete multiple elements in a map by key. |
| BPF_LINK_CREATE | 28 | Attach an eBPF program to a target_fd at the specified attach_type hook and return a file descriptor handle for managing the link. |
| BPF_LINK_UPDATE | 29 | Update the eBPF program in the specified link_fd to new_prog_fd. |
| BPF_LINK_GET_FD_BY_ID | 30 | Open a file descriptor for the eBPF Link corresponding to link_id. |
| BPF_LINK_GET_NEXT_ID | 31 | Fetch the next eBPF link currently loaded into the kernel. |
| BPF_ENABLE_STATS | 32 | Enable eBPF runtime statistics gathering. |
| BPF_ITER_CREATE | 33 | Create an iterator on top of the specified link_fd (as previously created using BPF_LINK_CREATE) and return a file descriptor that can be used to trigger the iteration. |
| BPF_LINK_DETACH | 34 | Forcefully detach the specified link_fd from its corresponding attachment point. |
| BPF_PROG_BIND_MAP | 35 | Bind a map to the lifetime of an eBPF program. |
| BPF_TOKEN_CREATE | 36 | Create BPF token with embedded information about what can be passed as an extra parameter to various bpf() syscall commands to grant BPF subsystem functionality to unprivileged processes. |

<a name="tetragon-BpfProgramType"></a>

### BpfProgramType

| Name | Number | Description |
| ---- | ------ | ----------- |
| BPF_PROG_TYPE_UNSPEC | 0 |  |
| BPF_PROG_TYPE_SOCKET_FILTER | 1 |  |
| BPF_PROG_TYPE_KPROBE | 2 |  |
| BPF_PROG_TYPE_SCHED_CLS | 3 |  |
| BPF_PROG_TYPE_SCHED_ACT | 4 |  |
| BPF_PROG_TYPE_TRACEPOINT | 5 |  |
| BPF_PROG_TYPE_XDP | 6 |  |
| BPF_PROG_TYPE_PERF_EVENT | 7 |  |
| BPF_PROG_TYPE_CGROUP_SKB | 8 |  |
| BPF_PROG_TYPE_CGROUP_SOCK | 9 |  |
| BPF_PROG_TYPE_LWT_IN | 10 |  |
| BPF_PROG_TYPE_LWT_OUT | 11 |  |
| BPF_PROG_TYPE_LWT_XMIT | 12 |  |
| BPF_PROG_TYPE_SOCK_OPS | 13 |  |
| BPF_PROG_TYPE_SK_SKB | 14 |  |
| BPF_PROG_TYPE_CGROUP_DEVICE | 15 |  |
| BPF_PROG_TYPE_SK_MSG | 16 |  |
| BPF_PROG_TYPE_RAW_TRACEPOINT | 17 |  |
| BPF_PROG_TYPE_CGROUP_SOCK_ADDR | 18 |  |
| BPF_PROG_TYPE_LWT_SEG6LOCAL | 19 |  |
| BPF_PROG_TYPE_LIRC_MODE2 | 20 |  |
| BPF_PROG_TYPE_SK_REUSEPORT | 21 |  |
| BPF_PROG_TYPE_FLOW_DISSECTOR | 22 |  |
| BPF_PROG_TYPE_CGROUP_SYSCTL | 23 |  |
| BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE | 24 |  |
| BPF_PROG_TYPE_CGROUP_SOCKOPT | 25 |  |
| BPF_PROG_TYPE_TRACING | 26 |  |
| BPF_PROG_TYPE_STRUCT_OPS | 27 |  |
| BPF_PROG_TYPE_EXT | 28 |  |
| BPF_PROG_TYPE_LSM | 29 |  |
| BPF_PROG_TYPE_SK_LOOKUP | 30 |  |
| BPF_PROG_TYPE_SYSCALL | 31 |  |
| BPF_PROG_TYPE_NETFILTER | 32 |  |

<a name="tetragon_capabilities-proto"></a>

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

<a name="tetragon-ProcessPrivilegesChanged"></a>

### ProcessPrivilegesChanged
Reasons of why the process privileges changed.

| Name | Number | Description |
| ---- | ------ | ----------- |
| PRIVILEGES_CHANGED_UNSET | 0 |  |
| PRIVILEGES_RAISED_EXEC_FILE_CAP | 1 | A privilege elevation happened due to the execution of a binary with file capability sets. The kernel supports associating capability sets with an executable file using `setcap` command. The file capability sets are stored in an extended attribute (see https://man7.org/linux/man-pages/man7/xattr.7.html) named `security.capability`. The file capability sets, in conjunction with the capability sets of the process, determine the process capabilities and privileges after the `execve` system call. For further reference, please check sections `File capability extended attribute versioning` and `Namespaced file capabilities` of the capabilities man pages: https://man7.org/linux/man-pages/man7/capabilities.7.html. The new granted capabilities can be listed inside the `process` object. |
| PRIVILEGES_RAISED_EXEC_FILE_SETUID | 2 | A privilege elevation happened due to the execution of a binary with set-user-ID to root. When a process with nonzero UIDs executes a binary with a set-user-ID to root also known as suid-root executable, then the kernel switches the effective user ID to 0 (root) which is a privilege elevation operation since it grants access to resources owned by the root user. The effective user ID is listed inside the `process_credentials` part of the `process` object. For further reading, section `Capabilities and execution of programs by root` of https://man7.org/linux/man-pages/man7/capabilities.7.html. Afterward the kernel recalculates the capability sets of the process and grants all capabilities in the permitted and effective capability sets, except those masked out by the capability bounding set. If the binary also have file capability sets then these bits are honored and the process gains just the capabilities granted by the file capability sets (i.e., not all capabilities, as it would occur when executing a set-user-ID to root binary that does not have any associated file capabilities). This is described in section `Set-user-ID-root programs that have file capabilities` of https://man7.org/linux/man-pages/man7/capabilities.7.html. The new granted capabilities can be listed inside the `process` object. There is one exception for the special treatments of set-user-ID to root execution receiving all capabilities, if the `SecBitNoRoot` bit of the Secure bits is set, then the kernel does not grant any capability. Please check section: `The securebits flags: establishing a capabilities-only environment` of the capabilities man pages: https://man7.org/linux/man-pages/man7/capabilities.7.html |
| PRIVILEGES_RAISED_EXEC_FILE_SETGID | 3 | A privilege elevation happened due to the execution of a binary with set-group-ID to root. When a process with nonzero GIDs executes a binary with a set-group-ID to root, the kernel switches the effective group ID to 0 (root) which is a privilege elevation operation since it grants access to resources owned by the root group. The effective group ID is listed inside the `process_credentials` part of the `process` object. |

<a name="tetragon-SecureBitsType"></a>

### SecureBitsType

| Name | Number | Description |
| ---- | ------ | ----------- |
| SecBitNotSet | 0 |  |
| SecBitNoRoot | 1 | When set UID 0 has no special privileges. When unset, inheritance of root-permissions and suid-root executable under compatibility mode is supported. If the effective uid of the new process is 0 then the effective and inheritable bitmasks of the executable file is raised. If the real uid is 0, the effective (legacy) bit of the executable file is raised. |
| SecBitNoRootLocked | 2 | Make bit-0 SecBitNoRoot immutable |
| SecBitNoSetUidFixup | 4 | When set, setuid to/from uid 0 does not trigger capability-&#34;fixup&#34;. When unset, to provide compatiblility with old programs relying on set*uid to gain/lose privilege, transitions to/from uid 0 cause capabilities to be gained/lost. |
| SecBitNoSetUidFixupLocked | 8 | Make bit-2 SecBitNoSetUidFixup immutable |
| SecBitKeepCaps | 16 | When set, a process can retain its capabilities even after transitioning to a non-root user (the set-uid fixup suppressed by bit 2). Bit-4 is cleared when a process calls exec(); setting both bit 4 and 5 will create a barrier through exec that no exec()&#39;d child can use this feature again. |
| SecBitKeepCapsLocked | 32 | Make bit-4 SecBitKeepCaps immutable |
| SecBitNoCapAmbientRaise | 64 | When set, a process cannot add new capabilities to its ambient set. |
| SecBitNoCapAmbientRaiseLocked | 128 | Make bit-6 SecBitNoCapAmbientRaise immutable |

<a name="tetragon_tetragon-proto"></a>

## tetragon/tetragon.proto

<a name="tetragon-BinaryProperties"></a>

### BinaryProperties

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| setuid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | If set then this is the set user ID used for execution |
| setgid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | If set then this is the set group ID used for execution |
| privileges_changed | [ProcessPrivilegesChanged](#tetragon-ProcessPrivilegesChanged) | repeated | The reasons why this binary execution changed privileges. Usually this happens when the process executes a binary with the set-user-ID to root or file capability sets. The final granted privileges can be listed inside the `process_credentials` or capabilities fields part of of the `process` object. |
| file | [FileProperties](#tetragon-FileProperties) |  | File properties in case the executed binary is: 1. An anonymous shared memory file https://man7.org/linux/man-pages/man7/shm_overview.7.html. 2. An anonymous file obtained with memfd API https://man7.org/linux/man-pages/man2/memfd_create.2.html. 3. Or it was deleted from the file system. |

<a name="tetragon-Capabilities"></a>

### Capabilities

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| permitted | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated | Permitted set indicates what capabilities the process can use. This is a limiting superset for the effective capabilities that the thread may assume. It is also a limiting superset for the capabilities that may be added to the inheritable set by a thread without the CAP_SETPCAP in its effective set. |
| effective | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated | Effective set indicates what capabilities are active in a process. This is the set used by the kernel to perform permission checks for the thread. |
| inheritable | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated | Inheritable set indicates which capabilities will be inherited by the current process when running as a root user. |

<a name="tetragon-Container"></a>

### Container

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Identifier of the container. |
| name | [string](#string) |  | Name of the container. |
| image | [Image](#tetragon-Image) |  | Image of the container. |
| start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Start time of the container. |
| pid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | Process identifier in the container namespace. |
| maybe_exec_probe | [bool](#bool) |  | If this is set true, it means that the process might have been originated from a Kubernetes exec probe. For this field to be true, the following must be true: 1. The binary field matches the first element of the exec command list for either liveness or readiness probe excluding the basename. For example, &#34;/bin/ls&#34; and &#34;ls&#34; are considered a match. 2. The arguments field exactly matches the rest of the exec command list. |
| security_context | [SecurityContext](#tetragon-SecurityContext) |  | The security context of the container |

<a name="tetragon-CreateContainer"></a>

### CreateContainer
CreateContainer informs the agent that a container was created
This is intented to be used by OCI hooks (but not limited to them) and corresponds to the
CreateContainer hook:
https://github.com/opencontainers/runtime-spec/blob/main/config.md#createcontainer-hooks.

The containerName, containerID, podName, podUID, and podNamespace fields are retrieved from the
annotations as a convenience, and may be left empty if the corresponding annotations are not
found.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cgroupsPath | [string](#string) |  | cgroupsPath is the cgroups path for the container. The path is expected to be relative to the cgroups mountpoint. See: https://github.com/opencontainers/runtime-spec/blob/58ec43f9fc39e0db229b653ae98295bfde74aeab/specs-go/config.go#L174 |
| rootDir | [string](#string) |  | rootDir is the absolute path of the root directory of the container. See: https://github.com/opencontainers/runtime-spec/blob/main/specs-go/config.go#L174 |
| annotations | [CreateContainer.AnnotationsEntry](#tetragon-CreateContainer-AnnotationsEntry) | repeated | annotations are the run-time annotations for the container see https://github.com/opencontainers/runtime-spec/blob/main/config.md#annotations |
| containerName | [string](#string) |  | containerName is the name of the container |
| containerID | [string](#string) |  | containerID is the id of the container |
| podName | [string](#string) |  | podName is the pod name |
| podUID | [string](#string) |  | podUID is the pod uid |
| podNamespace | [string](#string) |  | podNamespace is the namespace of the pod |
| containerImage | [string](#string) |  | containerImage is the full image location (repo &#43; image) |
| mounts | [Mount](#tetragon-Mount) | repeated | Mounts configures additional mounts (on top of Root). |

<a name="tetragon-CreateContainer-AnnotationsEntry"></a>

### CreateContainer.AnnotationsEntry

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |

<a name="tetragon-EnvVar"></a>

### EnvVar
Environment variable

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| Key | [string](#string) |  |  |
| Value | [string](#string) |  |  |

<a name="tetragon-FileProperties"></a>

### FileProperties

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inode | [InodeProperties](#tetragon-InodeProperties) |  | Inode of the file |
| path | [string](#string) |  | Path of the file |

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
| id | [string](#string) |  | Identifier of the container image composed of the registry path and the sha256. |
| name | [string](#string) |  | Name of the container image composed of the registry path and the tag. |

<a name="tetragon-InodeProperties"></a>

### InodeProperties

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | The inode number |
| links | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The inode links on the file system. If zero means the file is only in memory |

<a name="tetragon-KernelModule"></a>

### KernelModule

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Kernel module name |
| signature_ok | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  | If true the module signature was verified successfully. Depends on kernels compiled with CONFIG_MODULE_SIG option, for details please read: https://www.kernel.org/doc/Documentation/admin-guide/module-signing.rst |
| tainted | [TaintedBitsType](#tetragon-TaintedBitsType) | repeated | The module tainted flags that will be applied on the kernel. For further details please read: https://docs.kernel.org/admin-guide/tainted-kernels.html |

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
| user_namespace_arg | [KprobeUserNamespace](#tetragon-KprobeUserNamespace) |  | **Deprecated.**  |
| capability_arg | [KprobeCapability](#tetragon-KprobeCapability) |  |  |
| process_credentials_arg | [ProcessCredentials](#tetragon-ProcessCredentials) |  |  |
| user_ns_arg | [UserNamespace](#tetragon-UserNamespace) |  |  |
| module_arg | [KernelModule](#tetragon-KernelModule) |  |  |
| kernel_cap_t_arg | [string](#string) |  | Capabilities in hexadecimal format. |
| cap_inheritable_arg | [string](#string) |  | Capabilities inherited by a forked process in hexadecimal format. |
| cap_permitted_arg | [string](#string) |  | Capabilities that are currently permitted in hexadecimal format. |
| cap_effective_arg | [string](#string) |  | Capabilities that are actually used in hexadecimal format. |
| linux_binprm_arg | [KprobeLinuxBinprm](#tetragon-KprobeLinuxBinprm) |  |  |
| net_dev_arg | [KprobeNetDev](#tetragon-KprobeNetDev) |  |  |
| bpf_cmd_arg | [BpfCmd](#tetragon-BpfCmd) |  |  |
| syscall_id | [SyscallId](#tetragon-SyscallId) |  |  |
| sockaddr_arg | [KprobeSockaddr](#tetragon-KprobeSockaddr) |  |  |
| bpf_prog_arg | [KprobeBpfProg](#tetragon-KprobeBpfProg) |  |  |
| int32_list_arg | [KprobeInt32List](#tetragon-KprobeInt32List) |  |  |
| label | [string](#string) |  |  |

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

<a name="tetragon-KprobeBpfProg"></a>

### KprobeBpfProg

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ProgType | [string](#string) |  |  |
| InsnCnt | [uint32](#uint32) |  |  |
| ProgName | [string](#string) |  |  |

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
| permission | [string](#string) |  |  |

<a name="tetragon-KprobeInt32List"></a>

### KprobeInt32List

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| values | [int32](#int32) | repeated |  |

<a name="tetragon-KprobeLinuxBinprm"></a>

### KprobeLinuxBinprm

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| path | [string](#string) |  |  |
| flags | [string](#string) |  |  |
| permission | [string](#string) |  |  |

<a name="tetragon-KprobeNetDev"></a>

### KprobeNetDev

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |

<a name="tetragon-KprobePath"></a>

### KprobePath

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| mount | [string](#string) |  |  |
| path | [string](#string) |  |  |
| flags | [string](#string) |  |  |
| permission | [string](#string) |  |  |

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
| protocol | [string](#string) |  |  |
| family | [string](#string) |  |  |

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
| cookie | [uint64](#uint64) |  |  |
| state | [string](#string) |  |  |

<a name="tetragon-KprobeSockaddr"></a>

### KprobeSockaddr

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| family | [string](#string) |  |  |
| addr | [string](#string) |  |  |
| port | [uint32](#uint32) |  |  |

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

<a name="tetragon-Mount"></a>

### Mount

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| destination | [string](#string) |  | Destination is the absolute path where the mount will be placed in the container. |
| type | [string](#string) |  | Type specifies the mount kind. |
| source | [string](#string) |  | Source specifies the source path of the mount. |
| options | [string](#string) | repeated | Options are fstab style mount options. |

<a name="tetragon-Namespace"></a>

### Namespace

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inum | [uint32](#uint32) |  | Inode number of the namespace. |
| is_host | [bool](#bool) |  | Indicates if namespace belongs to host. |

<a name="tetragon-Namespaces"></a>

### Namespaces

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uts | [Namespace](#tetragon-Namespace) |  | Hostname and NIS domain name. |
| ipc | [Namespace](#tetragon-Namespace) |  | System V IPC, POSIX message queues. |
| mnt | [Namespace](#tetragon-Namespace) |  | Mount points. |
| pid | [Namespace](#tetragon-Namespace) |  | Process IDs. |
| pid_for_children | [Namespace](#tetragon-Namespace) |  | Process IDs for children processes. |
| net | [Namespace](#tetragon-Namespace) |  | Network devices, stacks, ports, etc. |
| time | [Namespace](#tetragon-Namespace) |  | Boot and monotonic clocks. |
| time_for_children | [Namespace](#tetragon-Namespace) |  | Boot and monotonic clocks for children processes. |
| cgroup | [Namespace](#tetragon-Namespace) |  | Cgroup root directory. |
| user | [Namespace](#tetragon-Namespace) |  | User and group IDs. |

<a name="tetragon-Pod"></a>

### Pod

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  | Kubernetes namespace of the Pod. |
| name | [string](#string) |  | Name of the Pod. |
| uid | [string](#string) |  | UID of the Pod. |
| container | [Container](#tetragon-Container) |  | Container of the Pod from which the process that triggered the event originates. |
| pod_labels | [Pod.PodLabelsEntry](#tetragon-Pod-PodLabelsEntry) | repeated | Contains all the labels of the pod. |
| workload | [string](#string) |  | Kubernetes workload of the Pod. |
| workload_kind | [string](#string) |  | Kubernetes workload kind (e.g. &#34;Deployment&#34;, &#34;DaemonSet&#34;) of the Pod. |
| pod_annotations | [Pod.PodAnnotationsEntry](#tetragon-Pod-PodAnnotationsEntry) | repeated | Contains all the annotations of the pod. |

<a name="tetragon-Pod-PodAnnotationsEntry"></a>

### Pod.PodAnnotationsEntry

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |

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
| pid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | Process identifier from host PID namespace. |
| uid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The effective User identifier used for permission checks. This field maps to the &#39;ProcessCredentials.euid&#39; field. Run with the `--enable-process-cred` flag to enable &#39;ProcessCredentials&#39; and get all the User and Group identifiers. |
| cwd | [string](#string) |  | Current working directory of the process. |
| binary | [string](#string) |  | Absolute path of the executed binary. |
| arguments | [string](#string) |  | Arguments passed to the binary at execution. |
| flags | [string](#string) |  | Flags are for debugging purposes only and should not be considered a reliable source of information. They hold various information about which syscalls generated events, use of internal Tetragon buffers, errors and more. - `execve` This event is generated by an execve syscall for a new process. See procFs for the other option. A correctly formatted event should either set execve or procFS (described next). - `procFS` This event is generated from a proc interface. This happens at Tetragon init when existing processes are being loaded into Tetragon event buffer. All events should have either execve or procFS set. - `truncFilename` Indicates a truncated processes filename because the buffer size is too small to contain the process filename. Consider increasing buffer size to avoid this. - `truncArgs` Indicates truncated the processes arguments because the buffer size was too small to contain all exec args. Consider increasing buffer size to avoid this. - `taskWalk` Primarily useful for debugging. Indicates a walked process hierarchy to find a parent process in the Tetragon buffer. This may happen when we did not receive an exec event for the immediate parent of a process. Typically means we are looking at a fork that in turn did another fork we don&#39;t currently track fork events exactly and instead push an event with the original parent exec data. This flag can provide this insight into the event if needed. - `miss` An error flag indicating we could not find parent info in the Tetragon event buffer. If this is set it should be reported to Tetragon developers for debugging. Tetragon will do its best to recover information about the process from available kernel data structures instead of using cached info in this case. However, args will not be available. - `needsAUID` An internal flag for Tetragon to indicate the audit has not yet been resolved. The BPF hooks look at this flag to determine if probing the audit system is necessary. - `errorFilename` An error flag indicating an error happened while reading the filename. If this is set it should be reported to Tetragon developers for debugging. - `errorArgs` An error flag indicating an error happened while reading the process args. If this is set it should be reported to Tetragon developers for debugging - `needsCWD` An internal flag for Tetragon to indicate the current working directory has not yet been resolved. The Tetragon hooks look at this flag to determine if probing the CWD is necessary. - `noCWDSupport` Indicates that CWD is removed from the event because the buffer size is too small. Consider increasing buffer size to avoid this. - `rootCWD` Indicates that CWD is the root directory. This is necessary to inform readers the CWD is not in the event buffer and is &#39;/&#39; instead. - `errorCWD` An error flag indicating an error occurred while reading the CWD of a process. If this is set it should be reported to Tetragon developers for debugging. - `clone` Indicates the process issued a clone before exec*. This is the general flow to exec* a new process, however its possible to replace the current process with a new process by doing an exec* without a clone. In this case the flag will be omitted and the same PID will be used by the kernel for both the old process and the newly exec&#39;d process. - `unknown` Indicates the process was not found in the process cache and contains just pid and start time. |
| start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Start time of the execution. |
| auid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | Audit user ID, this ID is assigned to a user upon login and is inherited by every process even when the user&#39;s identity changes. For example, by switching user accounts with su - john. |
| pod | [Pod](#tetragon-Pod) |  | Information about the the Kubernetes Pod where the event originated. |
| docker | [string](#string) |  | The 15 first digits of the container ID. |
| parent_exec_id | [string](#string) |  | Exec ID of the parent process. |
| refcnt | [uint32](#uint32) |  | Reference counter from the Tetragon process cache. |
| cap | [Capabilities](#tetragon-Capabilities) |  | Set of capabilities that define the permissions the process can execute with. |
| ns | [Namespaces](#tetragon-Namespaces) |  | Linux namespaces of the process, disabled by default, can be enabled by the `--enable-process-ns` flag. |
| tid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | Thread ID, note that for the thread group leader, tid is equal to pid. |
| process_credentials | [ProcessCredentials](#tetragon-ProcessCredentials) |  | Process credentials, disabled by default, can be enabled by the `--enable-process-cred` flag. |
| binary_properties | [BinaryProperties](#tetragon-BinaryProperties) |  | Executed binary properties. This field is only available on ProcessExec events. |
| user | [UserRecord](#tetragon-UserRecord) |  | UserRecord contains user information about the event. It is only supported when i) Tetragon is running as a systemd service or directly on the host, and ii) when the flag `--username-metadata` is set to &#34;unix&#34;. In this case, the information is retrieved from the traditional user database `/etc/passwd` and no name services lookups are performed. The resolution will only be attempted for processes in the host namespace. Note that this resolution happens in user-space, which means that mapping might have changed between the in-kernel BPF hook being executed and the username resolution. |
| in_init_tree | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  | If set to true, this process is containerized and is a member of the process tree rooted at pid=1 in its PID namespace. This is useful if, for example, you wish to discern whether a process was spawned using a tool like nsenter or kubectl exec. |
| environment_variables | [EnvVar](#tetragon-EnvVar) | repeated | Environment variables passed to the binary at execution. |

<a name="tetragon-ProcessCredentials"></a>

### ProcessCredentials

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The real user ID of the process&#39; owner. |
| gid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The real group ID of the process&#39; owner. |
| euid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The effective user ID used for permission checks. |
| egid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The effective group ID used for permission checks. |
| suid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The saved user ID. |
| sgid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The saved group ID. |
| fsuid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | the filesystem user ID used for filesystem access checks. Usually equals the euid. |
| fsgid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The filesystem group ID used for filesystem access checks. Usually equals the egid. |
| securebits | [SecureBitsType](#tetragon-SecureBitsType) | repeated | Secure management flags |
| caps | [Capabilities](#tetragon-Capabilities) |  | Set of capabilities that define the permissions the process can execute with. |
| user_ns | [UserNamespace](#tetragon-UserNamespace) |  | User namespace where the UIDs, GIDs and capabilities are relative to. |

<a name="tetragon-ProcessExec"></a>

### ProcessExec

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  | Process that triggered the exec. |
| parent | [Process](#tetragon-Process) |  | Immediate parent of the process. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |

<a name="tetragon-ProcessExit"></a>

### ProcessExit

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  | Process that triggered the exit. |
| parent | [Process](#tetragon-Process) |  | Immediate parent of the process. |
| signal | [string](#string) |  | Signal that the process received when it exited, for example SIGKILL or SIGTERM (list all signal names with `kill -l`). If there is no signal handler implemented for a specific process, we report the exit status code that can be found in the status field. |
| status | [uint32](#uint32) |  | Status code on process exit. For example, the status code can indicate if an error was encountered or the program exited successfully. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Date and time of the event. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |

<a name="tetragon-ProcessKprobe"></a>

### ProcessKprobe

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  | Process that triggered the kprobe. |
| parent | [Process](#tetragon-Process) |  | Immediate parent of the process. |
| function_name | [string](#string) |  | Symbol on which the kprobe was attached. |
| args | [KprobeArgument](#tetragon-KprobeArgument) | repeated | Arguments definition of the observed kprobe. |
| return | [KprobeArgument](#tetragon-KprobeArgument) |  | Return value definition of the observed kprobe. |
| action | [KprobeAction](#tetragon-KprobeAction) |  | Action performed when the kprobe matched. |
| kernel_stack_trace | [StackTraceEntry](#tetragon-StackTraceEntry) | repeated | Kernel stack trace to the call. |
| policy_name | [string](#string) |  | Name of the Tracing Policy that created that kprobe. |
| return_action | [KprobeAction](#tetragon-KprobeAction) |  | Action performed when the return kprobe executed. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |
| tags | [string](#string) | repeated | Tags of the Tracing Policy to categorize the event. |
| user_stack_trace | [StackTraceEntry](#tetragon-StackTraceEntry) | repeated | User-mode stack trace to the call. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |
| data | [KprobeArgument](#tetragon-KprobeArgument) | repeated | Data definition of the observed kprobe. |

<a name="tetragon-ProcessLoader"></a>

### ProcessLoader
loader sensor event triggered for loaded binary/library

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  | Process that triggered the loader. |
| path | [string](#string) |  | File path that is being loaded. |
| buildid | [bytes](#bytes) |  | Buildid of the file that is being loaded. |
| parent | [Process](#tetragon-Process) |  | Immediate parent of the process. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |

<a name="tetragon-ProcessLsm"></a>

### ProcessLsm

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| parent | [Process](#tetragon-Process) |  |  |
| function_name | [string](#string) |  | LSM hook name. |
| policy_name | [string](#string) |  | Name of the policy that created that LSM hook. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |
| args | [KprobeArgument](#tetragon-KprobeArgument) | repeated | Arguments definition of the observed LSM hook. |
| action | [KprobeAction](#tetragon-KprobeAction) |  | Action performed when the LSM hook matched. |
| tags | [string](#string) | repeated | Tags of the Tracing Policy to categorize the event. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |
| ima_hash | [string](#string) |  | IMA file hash. Format algorithm:value. |

<a name="tetragon-ProcessTracepoint"></a>

### ProcessTracepoint

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  | Process that triggered the tracepoint. |
| parent | [Process](#tetragon-Process) |  | Immediate parent of the process. |
| subsys | [string](#string) |  | Subsystem of the tracepoint. |
| event | [string](#string) |  | Event of the subsystem. |
| args | [KprobeArgument](#tetragon-KprobeArgument) | repeated | Arguments definition of the observed tracepoint. TODO: once we implement all we want, rename KprobeArgument to GenericArgument |
| policy_name | [string](#string) |  | Name of the policy that created that tracepoint. |
| action | [KprobeAction](#tetragon-KprobeAction) |  | Action performed when the tracepoint matched. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |
| tags | [string](#string) | repeated | Tags of the Tracing Policy to categorize the event. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |

<a name="tetragon-ProcessUprobe"></a>

### ProcessUprobe

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| parent | [Process](#tetragon-Process) |  |  |
| path | [string](#string) |  |  |
| symbol | [string](#string) |  |  |
| policy_name | [string](#string) |  | Name of the policy that created that uprobe. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |
| args | [KprobeArgument](#tetragon-KprobeArgument) | repeated | Arguments definition of the observed uprobe. |
| tags | [string](#string) | repeated | Tags of the Tracing Policy to categorize the event. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |
| offset | [uint64](#uint64) |  | uprobe offset (mutualy exclusive with symbol) |
| ref_ctr_offset | [uint64](#uint64) |  | uprobe ref_ctr_offset |
| action | [KprobeAction](#tetragon-KprobeAction) |  | Action performed when the uprobe hook matched. |
| data | [KprobeArgument](#tetragon-KprobeArgument) | repeated | Data definition of the observed uprobe. |

<a name="tetragon-ProcessUsdt"></a>

### ProcessUsdt

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| parent | [Process](#tetragon-Process) |  |  |
| path | [string](#string) |  |  |
| provider | [string](#string) |  |  |
| name | [string](#string) |  |  |
| policy_name | [string](#string) |  | Name of the policy that created that uprobe. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |
| args | [KprobeArgument](#tetragon-KprobeArgument) | repeated | Arguments definition of the observed uprobe. |
| tags | [string](#string) | repeated | Tags of the Tracing Policy to categorize the event. |
| ancestors | [Process](#tetragon-Process) | repeated | Ancestors of the process beyond the immediate parent. |
| action | [KprobeAction](#tetragon-KprobeAction) |  | Action performed when the USDT hook matched. |
| flags | [string](#string) |  | Flags are for debugging purposes only and should not be considered a reliable source of information. |

<a name="tetragon-RuntimeHookRequest"></a>

### RuntimeHookRequest
RuntimeHookRequest synchronously propagates information to the agent about run-time state.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| createContainer | [CreateContainer](#tetragon-CreateContainer) |  |  |

<a name="tetragon-RuntimeHookResponse"></a>

### RuntimeHookResponse

<a name="tetragon-SecurityContext"></a>

### SecurityContext

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| privileged | [bool](#bool) |  | True if this container is priviledged. |

<a name="tetragon-StackTraceEntry"></a>

### StackTraceEntry

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [uint64](#uint64) |  | linear address of the function in kernel or user space. |
| offset | [uint64](#uint64) |  | offset is the offset into the native instructions for the function. |
| symbol | [string](#string) |  | symbol is the symbol name of the function. |
| module | [string](#string) |  | module path for user space addresses. |

<a name="tetragon-SyscallId"></a>

### SyscallId

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |
| abi | [string](#string) |  |  |

<a name="tetragon-Test"></a>

### Test

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| arg0 | [uint64](#uint64) |  |  |
| arg1 | [uint64](#uint64) |  |  |
| arg2 | [uint64](#uint64) |  |  |
| arg3 | [uint64](#uint64) |  |  |

<a name="tetragon-UserNamespace"></a>

### UserNamespace

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| level | [google.protobuf.Int32Value](#google-protobuf-Int32Value) |  | Nested level of the user namespace. Init or host user namespace is at level 0. |
| uid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The owner user ID of the namespace |
| gid | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | The owner group ID of the namepace. |
| ns | [Namespace](#tetragon-Namespace) |  | The user namespace details that include the inode number of the namespace. |

<a name="tetragon-UserRecord"></a>

### UserRecord
User records

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | The UNIX username for this record. Corresponds to `pw_name` field of [struct passwd](https://man7.org/linux/man-pages/man3/getpwnam.3.html) and the `sp_namp` field of [struct spwd](https://man7.org/linux/man-pages/man3/getspnam.3.html). |

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
| KPROBE_ACTION_UNKNOWN | 0 | Unknown action |
| KPROBE_ACTION_POST | 1 | Post action creates an event (default action). |
| KPROBE_ACTION_FOLLOWFD | 2 | Post action creates a mapping between file descriptors and file names. |
| KPROBE_ACTION_SIGKILL | 3 | Sigkill action synchronously terminates the process. |
| KPROBE_ACTION_UNFOLLOWFD | 4 | Post action removes a mapping between file descriptors and file names. |
| KPROBE_ACTION_OVERRIDE | 5 | Override action modifies the return value of the call. |
| KPROBE_ACTION_COPYFD | 6 | Post action dupplicates a mapping between file descriptors and file names. |
| KPROBE_ACTION_GETURL | 7 | GetURL action issue an HTTP Get request against an URL from userspace. |
| KPROBE_ACTION_DNSLOOKUP | 8 | GetURL action issue a DNS lookup against an URL from userspace. |
| KPROBE_ACTION_NOPOST | 9 | NoPost action suppresses the transmission of the event to userspace. |
| KPROBE_ACTION_SIGNAL | 10 | Signal action sends specified signal to the process. |
| KPROBE_ACTION_TRACKSOCK | 11 | TrackSock action tracks socket. |
| KPROBE_ACTION_UNTRACKSOCK | 12 | UntrackSock action un-tracks socket. |
| KPROBE_ACTION_NOTIFYENFORCER | 13 | NotifyEnforcer action notifies enforcer sensor. |
| KPROBE_ACTION_CLEANUPENFORCERNOTIFICATION | 14 | CleanupEnforcerNotification action cleanups any state left by NotifyEnforcer |
| KPROBE_ACTION_SET | 15 | Set action sets first USDT argument |

<a name="tetragon-TaintedBitsType"></a>

### TaintedBitsType
Tainted bits to indicate if the kernel was tainted. For further details: https://docs.kernel.org/admin-guide/tainted-kernels.html

| Name | Number | Description |
| ---- | ------ | ----------- |
| TAINT_UNSET | 0 |  |
| TAINT_PROPRIETARY_MODULE | 1 | A proprietary module was loaded. |
| TAINT_FORCED_MODULE | 2 | A module was force loaded. |
| TAINT_FORCED_UNLOAD_MODULE | 4 | A module was force unloaded. |
| TAINT_STAGED_MODULE | 1024 | A staging driver was loaded. |
| TAINT_OUT_OF_TREE_MODULE | 4096 | An out of tree module was loaded. |
| TAINT_UNSIGNED_MODULE | 8192 | An unsigned module was loaded. Supported only on kernels built with CONFIG_MODULE_SIG option. |
| TAINT_KERNEL_LIVE_PATCH_MODULE | 32768 | The kernel has been live patched. |
| TAINT_TEST_MODULE | 262144 | Loading a test module. |

<a name="tetragon_events-proto"></a>

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

<a name="tetragon-CapFilter"></a>

### CapFilter
Filter over a set of Linux process capabilities. See `message Capabilities`
for more info.  WARNING: Multiple sets are ANDed. For example, if the
permitted filter matches, but the effective filter does not, the filter will
NOT match.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| permitted | [CapFilterSet](#tetragon-CapFilterSet) |  | Filter over the set of permitted capabilities. |
| effective | [CapFilterSet](#tetragon-CapFilterSet) |  | Filter over the set of effective capabilities. |
| inheritable | [CapFilterSet](#tetragon-CapFilterSet) |  | Filter over the set of inheritable capabilities. |

<a name="tetragon-CapFilterSet"></a>

### CapFilterSet
Capability set to filter over. NOTE: you may specify only ONE set here.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| any | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated | Match if the capability set contains any of the capabilities defined in this filter. |
| all | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated | Match if the capability set contains all of the capabilities defined in this filter. |
| exactly | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated | Match if the capability set exactly matches all of the capabilities defined in this filter. |
| none | [CapabilitiesType](#tetragon-CapabilitiesType) | repeated | Match if the capability set contains none of the capabilities defined in this filter. |

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
| pid_set | [uint32](#uint32) | repeated | Filter by the PID of a process and any of its descendants. Note that this filter is intended for testing and development purposes only and should not be used in production. In particular, PID cycling in the OS over longer periods of time may cause unexpected events to pass this filter. |
| event_set | [EventType](#tetragon-EventType) | repeated |  |
| pod_regex | [string](#string) | repeated | Filter by process.pod.name field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| arguments_regex | [string](#string) | repeated | Filter by process.arguments field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| labels | [string](#string) | repeated | Filter events by pod labels using Kubernetes label selector syntax: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors Note that this filter never matches events without the pod field (i.e. host process events). |
| policy_names | [string](#string) | repeated | Filter events by tracing policy names |
| capabilities | [CapFilter](#tetragon-CapFilter) |  | Filter events by Linux process capability |
| parent_binary_regex | [string](#string) | repeated | Filter parent process&#39; binary using RE2 regular expression syntax. |
| cel_expression | [string](#string) | repeated | Filter using CEL expressions. CEL filters support IP and CIDR notiation extensions from the k8s project. See https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#IP and https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#CIDR for details. |
| parent_arguments_regex | [string](#string) | repeated | Filter by process.parent.arguments field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| container_id | [string](#string) | repeated | Filter by the container ID in the process.docker field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| in_init_tree | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  | Filter containerized processes based on whether they are descendants of the container&#39;s init process. This can be used, for example, to watch for processes injected into a container via docker exec, kubectl exec, or similar mechanisms. |
| ancestor_binary_regex | [string](#string) | repeated | Filter ancestor processes&#39; binaries using RE2 regular expression syntax. |
| container_name_regex | [string](#string) | repeated | Filter by the container name in the process.pod.container field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |

<a name="tetragon-GetEventsRequest"></a>

### GetEventsRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allow_list | [Filter](#tetragon-Filter) | repeated | allow_list specifies a list of filters to apply to only return certain events. If multiple filters are specified, at least one of them has to match for an event to be included in the results. |
| deny_list | [Filter](#tetragon-Filter) | repeated | deny_list specifies a list of filters to apply to exclude certain events from the results. If multiple filters are specified, at least one of them has to match for an event to be excluded. If both allow_list and deny_list are specified, the results contain the set difference allow_list - deny_list. |
| aggregation_options | [AggregationOptions](#tetragon-AggregationOptions) |  | aggregation_options configures aggregation options for this request. If this field is not set, responses will not be aggregated. Note that currently only process_accept and process_connect events are aggregated. Other events remain unaggregated. |
| field_filters | [FieldFilter](#tetragon-FieldFilter) | repeated | Fields to include or exclude for events in the GetEventsResponse. Omitting this field implies that all fields will be included. Exclusion always takes precedence over inclusion in the case of conflicts. |

<a name="tetragon-GetEventsResponse"></a>

### GetEventsResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process_exec | [ProcessExec](#tetragon-ProcessExec) |  | ProcessExec event includes information about the execution of binaries and other related process metadata. |
| process_exit | [ProcessExit](#tetragon-ProcessExit) |  | ProcessExit event indicates how and when a process terminates. |
| process_kprobe | [ProcessKprobe](#tetragon-ProcessKprobe) |  | ProcessKprobe event contains information about the pre-defined functions and the process that invoked them. |
| process_tracepoint | [ProcessTracepoint](#tetragon-ProcessTracepoint) |  | ProcessTracepoint contains information about the pre-defined tracepoint and the process that invoked them. |
| process_loader | [ProcessLoader](#tetragon-ProcessLoader) |  |  |
| process_uprobe | [ProcessUprobe](#tetragon-ProcessUprobe) |  |  |
| process_throttle | [ProcessThrottle](#tetragon-ProcessThrottle) |  |  |
| process_lsm | [ProcessLsm](#tetragon-ProcessLsm) |  |  |
| process_usdt | [ProcessUsdt](#tetragon-ProcessUsdt) |  |  |
| test | [Test](#tetragon-Test) |  |  |
| rate_limit_info | [RateLimitInfo](#tetragon-RateLimitInfo) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. For an aggregated response, this field to set to the timestamp at which the event was observed for the first time in a given aggregation time window. |
| aggregation_info | [AggregationInfo](#tetragon-AggregationInfo) |  | aggregation_info contains information about aggregation results. This field is set only for aggregated responses. |
| cluster_name | [string](#string) |  | Name of the cluster where this event was observed. |
| node_labels | [GetEventsResponse.NodeLabelsEntry](#tetragon-GetEventsResponse-NodeLabelsEntry) | repeated | Labels associated with the node where this event was observed. |

<a name="tetragon-GetEventsResponse-NodeLabelsEntry"></a>

### GetEventsResponse.NodeLabelsEntry

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |

<a name="tetragon-ProcessThrottle"></a>

### ProcessThrottle

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [ThrottleType](#tetragon-ThrottleType) |  | Throttle type |
| cgroup | [string](#string) |  | Cgroup name |

<a name="tetragon-RateLimitInfo"></a>

### RateLimitInfo

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number_of_dropped_process_events | [uint64](#uint64) |  |  |

<a name="tetragon-RedactionFilter"></a>

### RedactionFilter

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| match | [Filter](#tetragon-Filter) | repeated | **Deprecated.** Deprecated, do not use. |
| redact | [string](#string) | repeated | RE2 regular expressions to use for redaction. Strings inside capture groups are redacted. |
| binary_regex | [string](#string) | repeated | RE2 regular expression to match binary name. If supplied, redactions will only be applied to matching processes. |

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
| PROCESS_LOADER | 11 |  |
| PROCESS_UPROBE | 12 |  |
| PROCESS_THROTTLE | 27 |  |
| PROCESS_LSM | 28 |  |
| PROCESS_USDT | 29 |  |
| TEST | 40000 |  |
| RATE_LIMIT_INFO | 40001 |  |

<a name="tetragon-FieldFilterAction"></a>

### FieldFilterAction
Determines the behavior of a field filter

| Name | Number | Description |
| ---- | ------ | ----------- |
| INCLUDE | 0 |  |
| EXCLUDE | 1 |  |

<a name="tetragon-ThrottleType"></a>

### ThrottleType

| Name | Number | Description |
| ---- | ------ | ----------- |
| THROTTLE_UNKNOWN | 0 |  |
| THROTTLE_START | 1 |  |
| THROTTLE_STOP | 2 |  |

<a name="tetragon_stack-proto"></a>

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

## tetragon/sensors.proto

<a name="tetragon-AddTracingPolicyRequest"></a>

### AddTracingPolicyRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| yaml | [string](#string) |  |  |

<a name="tetragon-AddTracingPolicyResponse"></a>

### AddTracingPolicyResponse

<a name="tetragon-ConfigureTracingPolicyRequest"></a>

### ConfigureTracingPolicyRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |
| enable | [bool](#bool) | optional |  |
| mode | [TracingPolicyMode](#tetragon-TracingPolicyMode) | optional |  |

<a name="tetragon-ConfigureTracingPolicyResponse"></a>

### ConfigureTracingPolicyResponse

<a name="tetragon-DeleteTracingPolicyRequest"></a>

### DeleteTracingPolicyRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |

<a name="tetragon-DeleteTracingPolicyResponse"></a>

### DeleteTracingPolicyResponse

<a name="tetragon-DisableSensorRequest"></a>

### DisableSensorRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |

<a name="tetragon-DisableSensorResponse"></a>

### DisableSensorResponse

<a name="tetragon-DisableTracingPolicyRequest"></a>

### DisableTracingPolicyRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |

<a name="tetragon-DisableTracingPolicyResponse"></a>

### DisableTracingPolicyResponse

<a name="tetragon-DumpProcessCacheReqArgs"></a>

### DumpProcessCacheReqArgs

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| skip_zero_refcnt | [bool](#bool) |  |  |
| exclude_execve_map_processes | [bool](#bool) |  |  |

<a name="tetragon-DumpProcessCacheResArgs"></a>

### DumpProcessCacheResArgs

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| processes | [ProcessInternal](#tetragon-ProcessInternal) | repeated |  |

<a name="tetragon-EnableSensorRequest"></a>

### EnableSensorRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |

<a name="tetragon-EnableSensorResponse"></a>

### EnableSensorResponse

<a name="tetragon-EnableTracingPolicyRequest"></a>

### EnableTracingPolicyRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |

<a name="tetragon-EnableTracingPolicyResponse"></a>

### EnableTracingPolicyResponse

<a name="tetragon-GetDebugRequest"></a>

### GetDebugRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flag | [ConfigFlag](#tetragon-ConfigFlag) |  |  |
| dump | [DumpProcessCacheReqArgs](#tetragon-DumpProcessCacheReqArgs) |  |  |

<a name="tetragon-GetDebugResponse"></a>

### GetDebugResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flag | [ConfigFlag](#tetragon-ConfigFlag) |  |  |
| level | [LogLevel](#tetragon-LogLevel) |  |  |
| processes | [DumpProcessCacheResArgs](#tetragon-DumpProcessCacheResArgs) |  |  |

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

<a name="tetragon-ListTracingPoliciesRequest"></a>

### ListTracingPoliciesRequest

<a name="tetragon-ListTracingPoliciesResponse"></a>

### ListTracingPoliciesResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| policies | [TracingPolicyStatus](#tetragon-TracingPolicyStatus) | repeated |  |

<a name="tetragon-ProcessInternal"></a>

### ProcessInternal

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon-Process) |  |  |
| color | [string](#string) |  |  |
| refcnt | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| refcnt_ops | [ProcessInternal.RefcntOpsEntry](#tetragon-ProcessInternal-RefcntOpsEntry) | repeated | refcnt_ops is a map of operations to refcnt change keys can be: - &#34;process&#43;&#43;&#34;: process increased refcnt (i.e. this process starts) - &#34;process--&#34;: process decreased refcnt (i.e. this process exits) - &#34;parent&#43;&#43;&#34;: parent increased refcnt (i.e. a process starts that has this process as a parent) - &#34;parent--&#34;: parent decreased refcnt (i.e. a process exits that has this process as a parent) - &#34;ancestor&#43;&#43;&#34;: ancestor increased refcnt (i.e. a process starts that has this process as an ancestor) - &#34;ancestor--&#34;: ancestor decreased refcnt (i.e. a process exits that has this process as an ancestor) |

<a name="tetragon-ProcessInternal-RefcntOpsEntry"></a>

### ProcessInternal.RefcntOpsEntry

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [int32](#int32) |  |  |

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
| name | [string](#string) |  | name is the name of the sensor |
| enabled | [bool](#bool) |  | enabled marks whether the sensor is enabled |
| collection | [string](#string) |  | collection is the collection the sensor belongs to (typically a tracing policy) |

<a name="tetragon-SetDebugRequest"></a>

### SetDebugRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flag | [ConfigFlag](#tetragon-ConfigFlag) |  |  |
| level | [LogLevel](#tetragon-LogLevel) |  |  |

<a name="tetragon-SetDebugResponse"></a>

### SetDebugResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flag | [ConfigFlag](#tetragon-ConfigFlag) |  |  |
| level | [LogLevel](#tetragon-LogLevel) |  |  |

<a name="tetragon-TracingPolicyActionCounters"></a>

### TracingPolicyActionCounters

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| post | [uint64](#uint64) |  | number of post events generated from the policy |
| signal | [uint64](#uint64) |  | number of signals sent from the policy |
| monitor_signal | [uint64](#uint64) |  | number of signals that were not sent because the policy was in monitor mode |
| override | [uint64](#uint64) |  | number of return overrides |
| monitor_override | [uint64](#uint64) |  | number of return overrides that did not occur because the policy was in monitor mode |
| notify_enforcer | [uint64](#uint64) |  | number of enforcer notifications triggered from the policy |
| monitor_notify_enforcer | [uint64](#uint64) |  | number of enforcer notifications that did not occur because the policy was in monitor mode |

<a name="tetragon-TracingPolicyStats"></a>

### TracingPolicyStats

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| action_counters | [TracingPolicyActionCounters](#tetragon-TracingPolicyActionCounters) |  |  |

<a name="tetragon-TracingPolicyStatus"></a>

### TracingPolicyStatus

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint64](#uint64) |  | id is the id of the policy |
| name | [string](#string) |  | name is the name of the policy |
| namespace | [string](#string) |  | namespace is the namespace of the policy (or empty of the policy is global) |
| info | [string](#string) |  | info is additional information about the policy |
| sensors | [string](#string) | repeated | sensors loaded in the scope of this policy |
| enabled | [bool](#bool) |  | **Deprecated.** indicating if the policy is enabled. Deprecated: use &#39;state&#39; instead. |
| filter_id | [uint64](#uint64) |  | filter ID of the policy used for k8s filtering |
| error | [string](#string) |  | potential error of the policy |
| state | [TracingPolicyState](#tetragon-TracingPolicyState) |  | current state of the tracing policy |
| kernel_memory_bytes | [uint64](#uint64) |  | the amount of kernel memory in bytes used by policy&#39;s sensors non-shared BPF maps (memlock) |
| mode | [TracingPolicyMode](#tetragon-TracingPolicyMode) |  | current mode of the tracing policy |
| stats | [TracingPolicyStats](#tetragon-TracingPolicyStats) | optional | stats of the tracing policy |

<a name="tetragon-ConfigFlag"></a>

### ConfigFlag
For now, we only want to support debug-related config flags to be configurable.

| Name | Number | Description |
| ---- | ------ | ----------- |
| CONFIG_FLAG_LOG_LEVEL | 0 |  |
| CONFIG_FLAG_DUMP_PROCESS_CACHE | 1 |  |

<a name="tetragon-LogLevel"></a>

### LogLevel

| Name | Number | Description |
| ---- | ------ | ----------- |
| LOG_LEVEL_PANIC | 0 |  |
| LOG_LEVEL_FATAL | 1 |  |
| LOG_LEVEL_ERROR | 2 |  |
| LOG_LEVEL_WARN | 3 |  |
| LOG_LEVEL_INFO | 4 |  |
| LOG_LEVEL_DEBUG | 5 |  |
| LOG_LEVEL_TRACE | 6 |  |

<a name="tetragon-TracingPolicyMode"></a>

### TracingPolicyMode

| Name | Number | Description |
| ---- | ------ | ----------- |
| TP_MODE_UNKNOWN | 0 |  |
| TP_MODE_ENFORCE | 1 |  |
| TP_MODE_MONITOR | 2 |  |
| TP_MODE_MONITOR_ONLY | 3 |  |

<a name="tetragon-TracingPolicyState"></a>

### TracingPolicyState

| Name | Number | Description |
| ---- | ------ | ----------- |
| TP_STATE_UNKNOWN | 0 | unknown state |
| TP_STATE_ENABLED | 1 | loaded and enabled |
| TP_STATE_DISABLED | 2 | loaded but disabled |
| TP_STATE_LOAD_ERROR | 3 | failed to load |
| TP_STATE_ERROR | 4 | failed during lifetime |
| TP_STATE_LOADING | 5 | in the process of loading |
| TP_STATE_UNLOADING | 6 | in the process of unloading |

<a name="tetragon-FineGuidanceSensors"></a>

### FineGuidanceSensors

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetEvents | [GetEventsRequest](#tetragon-GetEventsRequest) | [GetEventsResponse](#tetragon-GetEventsResponse) stream |  |
| GetHealth | [GetHealthStatusRequest](#tetragon-GetHealthStatusRequest) | [GetHealthStatusResponse](#tetragon-GetHealthStatusResponse) |  |
| AddTracingPolicy | [AddTracingPolicyRequest](#tetragon-AddTracingPolicyRequest) | [AddTracingPolicyResponse](#tetragon-AddTracingPolicyResponse) |  |
| DeleteTracingPolicy | [DeleteTracingPolicyRequest](#tetragon-DeleteTracingPolicyRequest) | [DeleteTracingPolicyResponse](#tetragon-DeleteTracingPolicyResponse) |  |
| ListTracingPolicies | [ListTracingPoliciesRequest](#tetragon-ListTracingPoliciesRequest) | [ListTracingPoliciesResponse](#tetragon-ListTracingPoliciesResponse) |  |
| ConfigureTracingPolicy | [ConfigureTracingPolicyRequest](#tetragon-ConfigureTracingPolicyRequest) | [ConfigureTracingPolicyResponse](#tetragon-ConfigureTracingPolicyResponse) | ConfigureTracingPolicy can be used to configure a loaded tracing policy. It can be used to: - enable/disable it - change its mode (enforcement vs monitoring) If multiple changes are requested and an error is encountered, the resulting state might have partial updates applied. In other words, the configuring a tracing policy is not atomic. |
| EnableTracingPolicy | [EnableTracingPolicyRequest](#tetragon-EnableTracingPolicyRequest) | [EnableTracingPolicyResponse](#tetragon-EnableTracingPolicyResponse) |  |
| DisableTracingPolicy | [DisableTracingPolicyRequest](#tetragon-DisableTracingPolicyRequest) | [DisableTracingPolicyResponse](#tetragon-DisableTracingPolicyResponse) |  |
| ListSensors | [ListSensorsRequest](#tetragon-ListSensorsRequest) | [ListSensorsResponse](#tetragon-ListSensorsResponse) |  |
| EnableSensor | [EnableSensorRequest](#tetragon-EnableSensorRequest) | [EnableSensorResponse](#tetragon-EnableSensorResponse) |  |
| DisableSensor | [DisableSensorRequest](#tetragon-DisableSensorRequest) | [DisableSensorResponse](#tetragon-DisableSensorResponse) |  |
| RemoveSensor | [RemoveSensorRequest](#tetragon-RemoveSensorRequest) | [RemoveSensorResponse](#tetragon-RemoveSensorResponse) |  |
| GetStackTraceTree | [GetStackTraceTreeRequest](#tetragon-GetStackTraceTreeRequest) | [GetStackTraceTreeResponse](#tetragon-GetStackTraceTreeResponse) |  |
| GetVersion | [GetVersionRequest](#tetragon-GetVersionRequest) | [GetVersionResponse](#tetragon-GetVersionResponse) |  |
| RuntimeHook | [RuntimeHookRequest](#tetragon-RuntimeHookRequest) | [RuntimeHookResponse](#tetragon-RuntimeHookResponse) |  |
| GetDebug | [GetDebugRequest](#tetragon-GetDebugRequest) | [GetDebugResponse](#tetragon-GetDebugResponse) |  |
| SetDebug | [SetDebugRequest](#tetragon-SetDebugRequest) | [SetDebugResponse](#tetragon-SetDebugResponse) |  |

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
