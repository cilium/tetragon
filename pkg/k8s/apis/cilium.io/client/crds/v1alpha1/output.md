# API Reference

Packages:

- [cilium.io/v1alpha1](#ciliumiov1alpha1)

# cilium.io/v1alpha1

Resource Types:

- [TracingPolicy](#tracingpolicy)




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
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
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
        <td><b><a href="#tracingpolicyspeckprobesindex">kprobes</a></b></td>
        <td>[]object</td>
        <td>
          A list of kprobe specs.<br/>
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
        <td><b><a href="#tracingpolicyspeckprobesindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
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
            <i>Enum</i>: int, uint32, int32, uint64, int64, char_buf, char_iovec, size_t, skb, sock, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used for char_buff data. When this value is false (default), the bpf program will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates that this argument should be read later (when the kretprobe for the symbol is triggered) because it might not be populated when the kprobe is triggered at the entrance of the function. For example, a buffer supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument. This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
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
            <i>Enum</i>: int, uint32, int32, uint64, int64, char_buf, char_iovec, size_t, skb, sock, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used for char_buff data. When this value is false (default), the bpf program will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates that this argument should be read later (when the kretprobe for the symbol is triggered) because it might not be populated when the kprobe is triggered at the entrance of the function. For example, a buffer supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument. This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.kprobes[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspeckprobesindex)</sup></sup>



KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The results of MatchPIDs and MatchArgs are ANDed.

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
          Action to execute.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost<br/>
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
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
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
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
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
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, Postfix, GreaterThan, LessThan, GT, LT<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, Postfix, GreaterThan, LessThan, GT, LT<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.podSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#tracingpolicyspecpodselector)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.

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
          operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
          <br/>
            <i>Enum</i>: In, NotIn, Exists, DoesNotExist<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.<br/>
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
        <td><b><a href="#tracingpolicyspectracepointsindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
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
            <i>Enum</i>: int, uint32, int32, uint64, int64, char_buf, char_iovec, size_t, skb, sock, string, fd, file, filename, path, nop, bpf_attr, perf_event, bpf_map, user_namespace, capability<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>maxData</b></td>
        <td>boolean</td>
        <td>
          Read maximum possible data (currently 327360). This field is only used for char_buff data. When this value is false (default), the bpf program will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon supports fetching up to 327360 bytes if this flag is turned on<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>returnCopy</b></td>
        <td>boolean</td>
        <td>
          This field is used only for char_buf and char_iovec types. It indicates that this argument should be read later (when the kretprobe for the symbol is triggered) because it might not be populated when the kprobe is triggered at the entrance of the function. For example, a buffer supplied to read(2) won't have content until kretprobe is triggered.<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sizeArgIndex</b></td>
        <td>integer</td>
        <td>
          Specifies the position of the corresponding size argument for this argument. This field is used only for char_buf and char_iovec types.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.tracepoints[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspectracepointsindex)</sup></sup>



KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The results of MatchPIDs and MatchArgs are ANDed.

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
          Action to execute.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost<br/>
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
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
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
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
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
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, Postfix, GreaterThan, LessThan, GT, LT<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, Postfix, GreaterThan, LessThan, GT, LT<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
        <td><b>symbol</b></td>
        <td>string</td>
        <td>
          Name of the traced symbol<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#tracingpolicyspecuprobesindexselectorsindex">selectors</a></b></td>
        <td>[]object</td>
        <td>
          Selectors to apply before producing trace output. Selectors are ORed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### TracingPolicy.spec.uprobes[index].selectors[index]
<sup><sup>[↩ Parent](#tracingpolicyspecuprobesindex)</sup></sup>



KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The results of MatchPIDs and MatchArgs are ANDed.

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
          Action to execute.<br/>
          <br/>
            <i>Enum</i>: Post, FollowFD, UnfollowFD, Sigkill, CopyFD, Override, GetUrl, DnsLookup, NoPost<br/>
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
        <td><b>argName</b></td>
        <td>integer</td>
        <td>
          An arg index for the filename for fdInstall action<br/>
          <br/>
            <i>Format</i>: int32<br/>
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
        <td><b>argUrl</b></td>
        <td>string</td>
        <td>
          A URL for the getUrl action<br/>
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
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, Postfix, GreaterThan, LessThan, GT, LT<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
            <i>Enum</i>: In, NotIn<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
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
        <td><b>index</b></td>
        <td>integer</td>
        <td>
          Position of the argument to apply fhe filter to.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Filter operation.<br/>
          <br/>
            <i>Enum</i>: Equal, NotEqual, Prefix, Postfix, GreaterThan, LessThan, GT, LT<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          Value to compare the argument against.<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>