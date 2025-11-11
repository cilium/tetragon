---
title: "Events"
weight: 1
description: "Documentation for Tetragon Events"
---

Tetragon's events are exposed to the system through either the gRPC
endpoint or JSON logs. Commands in this section assume the Getting
Started guide was used, but are general other than the namespaces
chosen and should work in most environments.

### JSON

The first way is to observe the raw json output from the stdout container log:

```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f
```

The raw JSON events provide Kubernetes API, identity metadata, and OS
level process visibility about the executed binary, its parent and the execution
time. A base Tetragon installation will produce `process_exec` and `process_exit`
events encoded in JSON as shown here,

<details><summary>Process execution event</summary>
<p>

```json
{
  "process_exec": {
    "process": {
      "exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4Njc0MzIxMzczOjUyNjk5",
      "pid": 52699,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/curl",
      "arguments": "https://ebpf.io/applications/#tetragon",
      "flags": "execve rootcwd",
      "start_time": "2023-10-06T22:03:57.700327580Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://551e161c47d8ff0eb665438a7bcd5b4e3ef5a297282b40a92b7c77d6bd168eb3",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-10-06T21:52:41Z",
          "pid": 49
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        },
        "workload": "xwing"
      },
      "docker": "551e161c47d8ff0eb665438a7bcd5b4",
      "parent_exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4NjcwODgzMjk5OjUyNjk5",
      "tid": 52699
    },
    "parent": {
      "exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4NjcwODgzMjk5OjUyNjk5",
      "pid": 52699,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "arguments": "-c \"curl https://ebpf.io/applications/#tetragon\"",
      "flags": "execve rootcwd clone",
      "start_time": "2023-10-06T22:03:57.696889812Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://551e161c47d8ff0eb665438a7bcd5b4e3ef5a297282b40a92b7c77d6bd168eb3",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-10-06T21:52:41Z",
          "pid": 49
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        },
        "workload": "xwing"
      },
      "docker": "551e161c47d8ff0eb665438a7bcd5b4",
      "parent_exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4NjQ1MjQ1ODM5OjUyNjg5",
      "tid": 52699
    }
  },
  "node_name": "gke-john-632-default-pool-7041cac0-9s95",
  "time": "2023-10-06T22:03:57.700326678Z"
}

```
</p>
</details>

Will only highlight a few important fields here. For a full specification of events see the Reference
section. All events in Tetragon contain a `process_exec` block to identify the process generating the
event. For execution events this is the primary block. For [Tracing Policy]({{< ref "/docs/concepts/tracing-policy" >}}) events the
hook that generated the event will attach further data to this. The `process_exec` event provides
a cluster wide unique id the `process_exec.exec_id` for this process along with the metadata expected
in a Kubernetes cluster  `process_exec.process.pod`. The binary and args being executed are part of
the event here `process_exec.process.binary` and `process_exec.process.args`. Finally, a `node_name`
and `time` provide the location and time for the event and will be present in all event types.

A default deployment writes the JSON log to `/var/run/cilium/tetragon/tetragon.log` where it can
be exported through normal log collection tooling, e.g. 'fluentd', logstash, etc.. The file will
be rotated and compressed by default. See [Helm Options] for details on how to customize this location.

#### Export Filtering

Export filters restrict the JSON event output to a subset of desirable events.
These export filters are configured as a line-separated list of JSON objects,
where each object can contain one or more filter expressions. Filters are
combined by taking the logical OR of each line-separated filter object and the
logical AND of sibling expressions within a filter object. As a concrete
example, suppose we had the following filter configuration:

```json
{"event_set": ["PROCESS_EXEC", "PROCESS_EXIT"], "namespace": ["foo"]}
{"event_set": ["PROCESS_KPROBE"]}
```

The above filter configuration would result in a match if:

- The event type is `PROCESS_EXEC` or `PROCESS_EXIT` AND the pod namespace is "foo"; OR
- The event type is `PROCESS_KPROBE`

Tetragon supports two groups of export filters: an allowlist and a denylist. If
neither is configured, all events are exported. If only an allowlist is
configured, event exports are considered default-deny, meaning only the events
in the allowlist are exported. The denylist takes precedence over the allowlist
in cases where two filter configurations match on the same event.

You can configure export filters using the provided helm options, command line
flags, or environment variables.

{{< caution >}}
The `denylist` and `allowlist` filters mentioned above only apply to events
exported as JSON files (e.g., through a configured `file` sink). These filters
do not affect events streamed via the gRPC API, which are consumed by tools
like the `tetra` CLI. You will still see unfiltered events when using the
`tetra` CLI, even if those events would be filtered out by `denylist` or
`allowlist` for JSON export.
{{< /caution >}}

##### List of Process Event Filters

The type for each filter attribute can be determined by referring to the 
[events.proto](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/events.proto#L38) file.

| Filter | Description | 
| ------ | ----------- |
| `event_set` | Filter process events by event types. Supported types include: `PROCESS_EXEC`, `PROCESS_EXIT`, `PROCESS_KPROBE`, `PROCESS_UPROBE`, `PROCESS_TRACEPOINT`, `PROCESS_LOADER` |
| `binary_regex` | Filter process events by a list of regular expressions of process binary names (e.g. `"^/home/kubernetes/bin/kubelet$"`). You can find the full syntax [here](https://github.com/google/re2/wiki/Syntax). | 
| `health_check` | Filter process events if their binary names match Kubernetes liveness / readiness probe commands of their corresponding pods. | 
| `namespace` | Filter by Kubernetes pod namespaces. An empty string (`""`) filters processes that do not belong to any pod namespace. | 
| `pid` | Filter by process PID. | 
| `pid_set` | Like `pid` but also includes processes that are descendants of the listed PIDs. | 
| `pod_regex` | Filter by pod name using a list of regular expressions. You can find the full syntax [here](https://github.com/google/re2/wiki/Syntax). | 
| `arguments_regex` | Filter by process arguments using a list of regular expressions. You can find the full syntax [here](https://github.com/google/re2/wiki/Syntax). | 
| `labels` | Filter events by pod labels using [Kubernetes label selector syntax](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors) Note that this filter never matches events without the pod field (i.e. host process events). |
| `policy_names` | Filter events by tracing policy names. |
| `capabilities` | Filter events by Linux process capability. |
| `cel_expression` | Filter using CEL expressions. CEL filters support IP and CIDR notiation extensions from the k8s project. See https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#IP and https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#CIDR for details. |
| `parent_binary_regex` | Filter process events by a list of regular expressions of parent process binary names (e.g. `"^/home/kubernetes/bin/kubelet$"`). You can find the full syntax [here](https://github.com/google/re2/wiki/Syntax). | 
| `parent_arguments_regex` | Filter by parent process arguments using a list of regular expressions. You can find the full syntax [here](https://github.com/google/re2/wiki/Syntax). | 
| `container_id` | Filter by the container ID in the process.docker field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax | 
| `in_init_tree` | Filter containerized processes based on whether they are descendants of the container's init process. This can be used, for example, to watch for processes injected into a container via docker exec, kubectl exec, or similar mechanisms. | 
| `ancestor_binary_regex` | Filter process events by a list of regular expressions of ancestor processes' binary names (e.g. `"^/home/kubernetes/bin/kubelet$"`). You can find the full syntax [here](https://github.com/google/re2/wiki/Syntax). | 

#### Field Filtering

In some cases, it is not desirable to include all of the fields exported in
Tetragon events by default. In these cases, you can use field filters to
restrict the set of exported fields for a given event type. Field filters are
configured similarly to export filters, as line-separated lists of JSON objects.

Field filters select fields using the [protobuf field mask syntax](https://protobuf.dev/reference/protobuf/google.protobuf/#field-mask)
under the `"fields"` key. You can define a path of fields using field
names separated by period (`.`) characters. To define multiple paths in
a single field filter, separate them with comma (`,`) characters. For
example, `"fields":"process.binary,parent.binary,pod.name"` would select
only the `process.binary`, `parent.binary`, and `pod.name` fields.

By default, a field filter applies to all process events, although you
can control this behaviour with the `"event_set"` key. For example, you
can apply a field filter to `PROCESS_KPROBE` and `PROCESS_TRACEPOINT` events
by specifying `"event_set":["PROCESS_KPROBE","PROCESS_TRACEPOINT"]` in the
filter definition.

Each field filter has an `"action"` that determines what the filter
should do with the selected field. The supported action types are
`"INCLUDE"` and `"EXCLUDE"`. A value of `"INCLUDE"` will cause the field
to appear in an event, while a value of `"EXCLUDE"` will hide the field.
In the absence of any field filter for a given event type, the export
will include all fields by default. Defining one or more `"INCLUDE"`
filters for a given event type changes that behaviour to exclude all
other event types by default.

As a simple example of the above, consider the case where we want to include
only `exec_id` and `parent_exec_id` in all event types except for
`PROCESS_EXEC`:

```json
{"fields":"process.exec_id,process.parent_exec_id", "event_set": ["PROCESS_EXEC"], "invert_event_set": true, "action": "INCLUDE"}
```

#### Redacting Sensitive Information

Since Tetragon traces the entire system, event exports might sometimes contain
sensitive information (for example, a secret passed via a command line argument
to a process). To prevent this information from being exfiltrated via Tetragon
JSON export, Tetragon provides a mechanism called Redaction Filters which can be
used to string patterns to redact from exported process arguments and environment
variables. These filters are written in JSON and passed to the Tetragon agent via
the `--redaction-filters` command line flag or the `redactionFilters` Helm value.

To perform redactions, redaction filters define RE2 regular expressions in the
`redact` field. Any capture groups in these RE2 regular expressions are redacted and
replaced with `"*****"`.

{{< note >}}
This feature uses RE2 as its regular expression library. Make sure that you follow
RE2 regular expression guidelines as you may observe unexpected results otherwise.
More information on RE2 syntax can be found [here](https://github.com/google/re2/wiki/Syntax).
{{< /note >}}

{{< warning >}}
When writing regular expressions in JSON, it is important to escape backslash
characters. For instance `\Wpasswd\W?` would be written as `{"redact": "\\Wpasswd\\W?"}`.
{{< /warning >}}

For more control, you can select which binary or binaries should have their
arguments or environment variables redacted with the `binary_regex` field.

As a concrete example, the following will redact all passwords passed to
processes with the `"--password"` argument:

```json
{"redact": ["--password(?:\\s+|=)(\\S*)"]}
```

Now, an event that contains the string `"--password=foo"` would have that string
replaced with `"--password=*****"`.

Suppose we also see some passwords passed via the -p shorthand for a specific binary, foo.
We can also redact these as follows:

```json
{"binary_regex": ["(?:^|/)foo$"], "redact": ["-p(?:\\s+|=)(\\S*)"]}
```

With both of the above redaction filters in place, we are now redacting all
password arguments.

Another example is to redact `SSHPASS` environment variable with:

```json
{"redact": ["(?:SSHPASS=)+(\\S+)"]}
```

Now, an event that contains the string `"SSHPASS=password"` would have that string
replaced with `"SSHPASS=*****"`.

It's also possible to store only requested environment variables with
'--filter-environment-variables VAR1[,VAR2..]` option.

### `tetra` CLI

A second way is to use the [`tetra`](https://github.com/cilium/tetragon/tree/main/cmd/tetra) CLI. This
has the advantage that it can also be used to filter and pretty print the output. The tool
allows filtering by process, pod, and other fields. To install tetra see the
[Tetra Installation Guide]({{< ref "/docs/installation/tetra-cli" >}})

To start printing events run:
```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact
```

The `tetra` CLI is also available inside `tetragon` container.

```shell
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

This was used in the quick start and generates a pretty printing of the events, To further
filter by a specific binary and/or pod do the following,

```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --processes curl --pod xwing
```

Will filter and report just the relevant events.

```
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon 60
```

### gRPC

In addition Tetragon can expose a gRPC endpoint listeners may attach to. The
gRPC is exposed by default helm install on `localhost:54321`, but the address
can be configured  with the `--server-address` option. This can be
set from helm with the `tetragon.grpc.address` flag or disabled completely if
needed with `tetragon.grpc.enabled`.

```shell
helm install tetragon cilium/tetragon -n kube-system --set tetragon.grpc.enabled=true --set tetragon.grpc.address=localhost:54321
```

An example gRPC endpoint is the Tetra CLI when its not piped JSON output directly,

```shell
 kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```
