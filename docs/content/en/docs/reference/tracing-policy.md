---
title: "Tracing Policy"
description: "This reference documentation is generated from the Tracing Policy CRD specification, detailing its fields and usage."
weight: 5
---

A [TracingPolicy](#tracingpolicy) is a user-configurable Kubernetes custom
resource (CR) that defines how Tetragon observes events in both the kernel
and userspace using eBPF. It supports a variety of hook points including
[kprobes](#tracingpolicyspeckprobesindex), [uprobes](#tracingpolicyspecuprobesindex),
[tracepoints](#tracingpolicyspectracepointsindex), [LSM hooks](#tracingpolicyspeclsmhooksindex),
and [USDTs](#tracingpolicyspecusdtsindex), giving users fine-grained control
over what to trace and what actions to take. Policies consist of hook points,
selectors for in-kernel filtering, and optional actions that can be executed
when a match occurs.

Tracing policies can be loaded and unloaded dynamically at runtime or applied
at startup using configuration flags. Although structured as Kubernetes CRs,
they can also be used in non-Kubernetes environments via
[Tetragon’s CLI](https://tetragon.io/docs/installation/tetra-cli/) or
[daemon flags](https://tetragon.io/docs/reference/daemon-configuration/). In
Kubernetes, policies can be managed using
[kubectl](https://kubernetes.io/docs/reference/kubectl/) or tools like
[Argo CD](https://argo-cd.readthedocs.io/en/stable/).

## Tracing Policy API Reference

Packages:

- [cilium.io/v1alpha1](#ciliumiov1alpha1)

## cilium.io/v1alpha1

Resource Types:
   
- [TracingPolicy](#tracingpolicy)   
- [TracingPolicyNamespaced](#tracingpolicynamespaced)

   

## TracingPolicy
<sup><sup>[↩ Parent](#ciliumiov1alpha1 )</sup></sup>







<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>cilium.io/v1alpha1</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>TracingPolicy</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspec">spec</a></b></td>
        <td>object</td>
        <td>
          Tracing policy specification.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec
<sup><sup>[↩ Parent](#tracingpolicy)</sup></sup>


Tracing policy specification.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspeccontainerselector">containerSelector</a></b></td>
        <td>object</td>
        <td>
          ContainerSelector selects containers that this policy applies to.
A map of container fields will be constructed in the same way as a map of labels.
The name of the field represents the label "key", and the value of the field - label "value".
Currently, only the "name" field is supported.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecenforcersindex">enforcers</a></b></td>
        <td>[]object</td>
        <td>
          A enforcer spec.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindex">kprobes</a></b></td>
        <td>[]object</td>
        <td>
          A list of kprobe specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclistsindex">lists</a></b></td>
        <td>[]object</td>
        <td>
          A list of list specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>loader</b></td>
        <td>boolean</td>
        <td>
          Enable loader events<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindex">lsmhooks</a></b></td>
        <td>[]object</td>
        <td>
          A list of uprobe specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecoptionsindex">options</a></b></td>
        <td>[]object</td>
        <td>
          A list of overloaded options<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecpodselector">podSelector</a></b></td>
        <td>object</td>
        <td>
          PodSelector selects pods that this policy applies to<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindex">tracepoints</a></b></td>
        <td>[]object</td>
        <td>
          A list of tracepoint specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindex">uprobes</a></b></td>
        <td>[]object</td>
        <td>
          A list of uprobe specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindex">usdts</a></b></td>
        <td>[]object</td>
        <td>
          A list of usdt specs.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.containerSelector
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>


ContainerSelector selects containers that this policy applies to.
A map of container fields will be constructed in the same way as a map of labels.
The name of the field represents the label "key", and the value of the field - label "value".
Currently, only the "name" field is supported.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspeccontainerselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.containerSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#tracingpolicyspeccontainerselector)</sup></sup>


A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Exists, DoesNotExist<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.enforcers[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>calls</b></td>
        <td>[]string</td>
        <td>
          Calls where enforcer is executed in<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>call</b></td>
        <td>string</td>
        <td>
          Name of the function to apply the kprobe spec to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexdataindex">data</a></b></td>
        <td>[]object</td>
        <td>
          A list of data to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexignore">ignore</a></b></td>
        <td>object</td>
        <td>
          Conditions for ignoring this kprobe<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>return</b></td>
        <td>boolean</td>
        <td>
          Indicates whether to collect return value of the traced function.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexreturnarg">returnArg</a></b></td>
        <td>object</td>
        <td>
          A return argument to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnArgAction</b></td>
        <td>string</td>
        <td>
          An action to perform on the return argument.
Available actions are: Post;TrackSock;UntrackSock<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed and short-circuited.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>syscall</b></td>
        <td>boolean</td>
        <td>
          Indicates whether the traced function is a syscall.<br/>
          <br/>
            <i>Default</i>: true<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].data[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].ignore
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindex)</sup></sup>


Conditions for ignoring this kprobe

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>callNotFound</b></td>
        <td>boolean</td>
        <td>
          Ignores calls that are not present in the system<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].returnArg
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindex)</sup></sup>


A return argument to include in the trace output.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lists[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the list<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>pattern</b></td>
        <td>string</td>
        <td>
          Pattern for 'generated' lists.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Indicates the type of the list values.<br/>
          <br/>
            <i>Enum</i>: syscalls, generated_syscalls, generated_ftrace<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>validated</b></td>
        <td>boolean</td>
        <td>
          List was validated<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Values of the list<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>hook</b></td>
        <td>string</td>
        <td>
          Name of the function to apply the kprobe spec to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspeclsmhooksindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.lsmhooks[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.options[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the option<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>value</b></td>
        <td>string</td>
        <td>
          Value of the option<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.podSelector
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>


PodSelector selects pods that this policy applies to

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspecpodselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.podSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#tracingpolicyspecpodselector)</sup></sup>


A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Exists, DoesNotExist<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>event</b></td>
        <td>string</td>
        <td>
          Tracepoint event<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>subsystem</b></td>
        <td>string</td>
        <td>
          Tracepoint subsystem<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>raw</b></td>
        <td>boolean</td>
        <td>
          Enable raw tracepoint arguments<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>path</b></td>
        <td>string</td>
        <td>
          Name of the traced binary<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>addrs</b></td>
        <td>[]integer</td>
        <td>
          List of the traced addresses<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>btfPath</b></td>
        <td>string</td>
        <td>
          path for a BTF file for the traced binary<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexdataindex">data</a></b></td>
        <td>[]object</td>
        <td>
          A list of data to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>offsets</b></td>
        <td>[]integer</td>
        <td>
          List of the traced offsets<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>refCtrOffsets</b></td>
        <td>[]integer</td>
        <td>
          List of the traced ref_ctr_offsets<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>return</b></td>
        <td>boolean</td>
        <td>
          Indicates whether to collect return value of the traced function.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexreturnarg">returnArg</a></b></td>
        <td>object</td>
        <td>
          A return argument to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>symbols</b></td>
        <td>[]string</td>
        <td>
          List of the traced symbols<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].data[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].returnArg
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindex)</sup></sup>


A return argument to include in the trace output.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index]
<sup><sup>[↩ Parent](#tracingpolicyspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Usdt name<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>path</b></td>
        <td>string</td>
        <td>
          Name of the traced binary<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>provider</b></td>
        <td>string</td>
        <td>
          Usdt provider name<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>btfPath</b></td>
        <td>string</td>
        <td>
          path for a BTF file for the traced binary<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecusdtsindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.usdts[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicyspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>    

## TracingPolicyNamespaced
<sup><sup>[↩ Parent](#ciliumiov1alpha1 )</sup></sup>







<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>cilium.io/v1alpha1</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>TracingPolicyNamespaced</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspec">spec</a></b></td>
        <td>object</td>
        <td>
          Tracing policy specification.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec
<sup><sup>[↩ Parent](#tracingpolicynamespaced)</sup></sup>


Tracing policy specification.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspeccontainerselector">containerSelector</a></b></td>
        <td>object</td>
        <td>
          ContainerSelector selects containers that this policy applies to.
A map of container fields will be constructed in the same way as a map of labels.
The name of the field represents the label "key", and the value of the field - label "value".
Currently, only the "name" field is supported.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecenforcersindex">enforcers</a></b></td>
        <td>[]object</td>
        <td>
          A enforcer spec.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindex">kprobes</a></b></td>
        <td>[]object</td>
        <td>
          A list of kprobe specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclistsindex">lists</a></b></td>
        <td>[]object</td>
        <td>
          A list of list specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>loader</b></td>
        <td>boolean</td>
        <td>
          Enable loader events<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindex">lsmhooks</a></b></td>
        <td>[]object</td>
        <td>
          A list of uprobe specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecoptionsindex">options</a></b></td>
        <td>[]object</td>
        <td>
          A list of overloaded options<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecpodselector">podSelector</a></b></td>
        <td>object</td>
        <td>
          PodSelector selects pods that this policy applies to<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindex">tracepoints</a></b></td>
        <td>[]object</td>
        <td>
          A list of tracepoint specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindex">uprobes</a></b></td>
        <td>[]object</td>
        <td>
          A list of uprobe specs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindex">usdts</a></b></td>
        <td>[]object</td>
        <td>
          A list of usdt specs.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.containerSelector
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>


ContainerSelector selects containers that this policy applies to.
A map of container fields will be constructed in the same way as a map of labels.
The name of the field represents the label "key", and the value of the field - label "value".
Currently, only the "name" field is supported.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspeccontainerselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.containerSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeccontainerselector)</sup></sup>


A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Exists, DoesNotExist<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.enforcers[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>calls</b></td>
        <td>[]string</td>
        <td>
          Calls where enforcer is executed in<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>call</b></td>
        <td>string</td>
        <td>
          Name of the function to apply the kprobe spec to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexdataindex">data</a></b></td>
        <td>[]object</td>
        <td>
          A list of data to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexignore">ignore</a></b></td>
        <td>object</td>
        <td>
          Conditions for ignoring this kprobe<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>return</b></td>
        <td>boolean</td>
        <td>
          Indicates whether to collect return value of the traced function.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexreturnarg">returnArg</a></b></td>
        <td>object</td>
        <td>
          A return argument to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnArgAction</b></td>
        <td>string</td>
        <td>
          An action to perform on the return argument.
Available actions are: Post;TrackSock;UntrackSock<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed and short-circuited.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>syscall</b></td>
        <td>boolean</td>
        <td>
          Indicates whether the traced function is a syscall.<br/>
          <br/>
            <i>Default</i>: true<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].data[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].ignore
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindex)</sup></sup>


Conditions for ignoring this kprobe

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>callNotFound</b></td>
        <td>boolean</td>
        <td>
          Ignores calls that are not present in the system<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].returnArg
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindex)</sup></sup>


A return argument to include in the trace output.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeckprobesindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.kprobes[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeckprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lists[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the list<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>pattern</b></td>
        <td>string</td>
        <td>
          Pattern for 'generated' lists.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Indicates the type of the list values.<br/>
          <br/>
            <i>Enum</i>: syscalls, generated_syscalls, generated_ftrace<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>validated</b></td>
        <td>boolean</td>
        <td>
          List was validated<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Values of the list<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>hook</b></td>
        <td>string</td>
        <td>
          Name of the function to apply the kprobe spec to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspeclsmhooksindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.lsmhooks[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspeclsmhooksindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.options[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the option<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>value</b></td>
        <td>string</td>
        <td>
          Value of the option<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.podSelector
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>


PodSelector selects pods that this policy applies to

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspecpodselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.podSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecpodselector)</sup></sup>


A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Exists, DoesNotExist<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>event</b></td>
        <td>string</td>
        <td>
          Tracepoint event<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>subsystem</b></td>
        <td>string</td>
        <td>
          Tracepoint subsystem<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>raw</b></td>
        <td>boolean</td>
        <td>
          Enable raw tracepoint arguments<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspectracepointsindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.tracepoints[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspectracepointsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>path</b></td>
        <td>string</td>
        <td>
          Name of the traced binary<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>addrs</b></td>
        <td>[]integer</td>
        <td>
          List of the traced addresses<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>btfPath</b></td>
        <td>string</td>
        <td>
          path for a BTF file for the traced binary<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexdataindex">data</a></b></td>
        <td>[]object</td>
        <td>
          A list of data to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>offsets</b></td>
        <td>[]integer</td>
        <td>
          List of the traced offsets<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>refCtrOffsets</b></td>
        <td>[]integer</td>
        <td>
          List of the traced ref_ctr_offsets<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>return</b></td>
        <td>boolean</td>
        <td>
          Indicates whether to collect return value of the traced function.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexreturnarg">returnArg</a></b></td>
        <td>object</td>
        <td>
          A return argument to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>symbols</b></td>
        <td>[]string</td>
        <td>
          List of the traced symbols<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].data[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].returnArg
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindex)</sup></sup>


A return argument to include in the trace output.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecuprobesindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.uprobes[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecuprobesindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspec)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Usdt name<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>path</b></td>
        <td>string</td>
        <td>
          Name of the traced binary<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>provider</b></td>
        <td>string</td>
        <td>
          Usdt provider name<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexargsindex">args</a></b></td>
        <td>[]object</td>
        <td>
          A list of function arguments to include in the trace output.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>btfPath</b></td>
        <td>string</td>
        <td>
          path for a BTF file for the traced binary<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          A short message of 256 characters max that will be included
in the event output to inform users what is going on.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>tags</b></td>
        <td>[]string</td>
        <td>
          Tags to categorize the event, will be include in the event output.
Maximum of 16 Tags are supported.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].args[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Argument type.<br/>
          <br/>
            <i>Enum</i>: auto, int, sint8, int8, uint8, sint16, int16, uint16, uint32, sint32, int32, ulong, uint64, size_t, long, sint64, int64, char_buf, char_iovec, skb, sock, sockaddr, socket, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability, kiocb, iov_iter, cred, const_buf, load_info, module, syscall64, kernel_cap_t, cap_inheritable, cap_permitted, cap_effective, linux_binprm, data_loc, net_device, bpf_cmd, dentry, bpf_prog<br/>
            <i>Default</i>: auto<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>btfType</b></td>
        <td>string</td>
        <td>
          Type of original argument. This is currently only used in UsdtSpecs and UprobeSpecs for arguments with
the Resolve attribute set. It relies on the BTF file defined by BTFPath to extract the
type.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>label</b></td>
        <td>string</td>
        <td>
          Label to output in the JSON<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used
for char_buff data. When this value is false (default), the bpf program
will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resolve</b></td>
        <td>string</td>
        <td>
          Resolve the path to a specific attribute<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates
that this argument should be read later (when the kretprobe for the
symbol is triggered) because it might not be populated when the kprobe
is triggered at the entrance of the function. For example, a buffer
supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument.
This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>source</b></td>
        <td>string</td>
        <td>
          Source of the data, if missing the default if function arguments<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindex)</sup></sup>


KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
results of MatchPIDs and MatchArgs are ANDed.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchactionsindex">matchActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when this selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchargsindex">matchArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchbinariesindex">matchBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of binary exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchcapabilitiesindex">matchCapabilities</a></b></td>
        <td>[]object</td>
        <td>
          A list of capabilities and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchcapabilitychangesindex">matchCapabilityChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for capabilities changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchdataindex">matchData</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchData are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchnamespacechangesindex">matchNamespaceChanges</a></b></td>
        <td>[]object</td>
        <td>
          IDs for namespace changes<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchnamespacesindex">matchNamespaces</a></b></td>
        <td>[]object</td>
        <td>
          A list of namespaces and IDs<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchpidsindex">matchPIDs</a></b></td>
        <td>[]object</td>
        <td>
          A list of process ID filters. MatchPIDs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchparentbinariesindex">matchParentBinaries</a></b></td>
        <td>[]object</td>
        <td>
          A list of process parent exec name filters.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchreturnactionsindex">matchReturnActions</a></b></td>
        <td>[]object</td>
        <td>
          A list of actions to execute when MatchReturnArgs selector matches<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#tracingpolicynamespacedspecusdtsindexselectorsindexmatchreturnargsindex">matchReturnArgs</a></b></td>
        <td>[]object</td>
        <td>
          A list of argument filters. MatchArgs are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchCapabilities[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchCapabilityChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Capabilities to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>isNamespaceCapability</b></td>
        <td>boolean</td>
        <td>
          Indicates whether these caps are namespace caps.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type of capabilities<br/>
          <br/>
            <i>Enum</i>: Effective, Inheritable, Permitted<br/>
            <i>Default</i>: Effective<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchData[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchNamespaceChanges[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace types (e.g., Mnt, Pid) to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchNamespaces[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>namespace</b></td>
        <td>enum</td>
        <td>
          Namespace selector name.<br/>
          <br/>
            <i>Enum</i>: Uts, Ipc, Mnt, Pid, PidForChildren, Net, Time, TimeForChildren, Cgroup, User<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Namespace selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Namespace IDs (or host_ns for host namespace) of namespaces to match.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchPIDs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          PID selector operator.<br/>
          <br/>
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]integer</td>
        <td>
          Process IDs to match.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followForks</b></td>
        <td>boolean</td>
        <td>
          Matches any descendant processes of the matching PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>isNamespacePID</b></td>
        <td>boolean</td>
        <td>
          Indicates whether PIDs are namespace PIDs.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchParentBinaries[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>followChildren</b></td>
        <td>boolean</td>
        <td>
          In addition to binaries, match children processes of specified binaries.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchReturnActions[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>action</b></td>
        <td>enum</td>
        <td>
          Action to execute.
NOTE: actions FollowFD, UnfollowFD, and CopyFD are marked as deprecated and planned to
be removed in version 1.5.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock, NotifyEnforcer, CleanupEnforcerNotification, Set<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>argError</b></td>
        <td>integer</td>
        <td>
          error value for override action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFd</b></td>
        <td>integer</td>
        <td>
          An arg index for the fd for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argFqdn</b></td>
        <td>string</td>
        <td>
          A FQDN to lookup for the dnsLookup action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argIndex</b></td>
        <td>integer</td>
        <td>
          An arg index for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argRegs</b></td>
        <td>[]string</td>
        <td>
          An arg value for the regs action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSig</b></td>
        <td>integer</td>
        <td>
          A signal number for signal action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argSock</b></td>
        <td>integer</td>
        <td>
          An arg index for the sock for trackSock and untrackSock actions<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>argValue</b></td>
        <td>integer</td>
        <td>
          An arg value for the set action<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imaHash</b></td>
        <td>boolean</td>
        <td>
          Enable collection of file hashes from integrity subsystem.
Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>kernelStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable kernel stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimit</b></td>
        <td>string</td>
        <td>
          A time period within which repeated messages will not be posted. Can be
specified in seconds (default or with 's' suffix), minutes ('m' suffix)
or hours ('h' suffix). Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>rateLimitScope</b></td>
        <td>string</td>
        <td>
          The scope of the provided rate limit argument. Can be "thread" (default),
"process" (all threads for the same process), or "global". If "thread" is
selected then rate limiting applies per thread; if "process" is selected
then rate limiting applies per process; if "global" is selected then rate
limiting applies regardless of which process or thread caused the action.
Only valid with the post action and with a rateLimit specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>userStackTrace</b></td>
        <td>boolean</td>
        <td>
          Enable user stack trace export. Only valid with the post action.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicyNamespaced.spec.usdts[index].selectors[index].matchReturnArgs[index]
<sup><sup>[↩ Parent](#tracingpolicynamespacedspecusdtsindexselectorsindex)</sup></sup>




<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, NotPrefix, Postfix, NotPostfix, GreaterThan, LessThan, GT, LT, Mask, SPort, NotSPort, SPortPriv, NotSportPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State, InMap, NotInMap, CapabilitiesGained, InRange, NotInRange, SubString, SubStringIgnCase, FileType, NotFileType<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>args</b></td>
        <td>[]integer</td>
        <td>
          Position of the operator arguments (in spec file) to apply fhe filter to.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument (in function prototype) to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table> 
