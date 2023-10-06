---
title: "Execution monitoring"
weight: 2
description: "Execution Traces with Tetragon"
---

At the core of Tetragon is the tracking of all executions in a kubernetes cluster,
virtual machines, and baremetal systems. This creates the foundation that allows
Tetragon to attribute all system behavior back to a specific binary and its
associated metadata (container, pod, node, and cluster).

## Observe Tetragon Execution Events

Tetragon exposes the execution trace over JSON logs and GRPC stream. The user
can then observe all executions in the system.

The following command can be used to observe exec events.

{{< tabpane >}}
{{< tab header="K8s" >}}          
kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Docker" >}}          
docker exec tetragon-container tetra getevents -o compact
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Systemd" >}}
{{< /tab >}}                                                                                                                                                                                   
{{< /tabpane >}}

This will print a compact form of the exec logs. For an example we do the following
with the demo application.

```
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon
```
The CLI will print a compact form of the event to the terminal

```
🚀 process default/xwing /bin/bash -c "curl https://ebpf.io/applications/#tetragon" 
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon 
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon 60 

```

The compact exec event contains the event type, the pod name, the binary and the args. The exit event will include the return code, in the case of curl `60` above.

For the complete exec event in JSON format remove the compact option.

{{< tabpane >}}
{{< tab header="K8s" >}}          
kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Docker" >}}          
docker exec tetragon-container tetra getevents
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Systemd" >}}
{{< /tab >}}                                                                                                                                                                                   
{{< /tabpane >}}

This will include a lot more details related the binary and event. A full example of the above curl is hown here,

```
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

## What's next
