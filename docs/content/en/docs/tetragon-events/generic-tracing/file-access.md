---
title: "Use case: file access"
weight: 1
description: "Monitor file access using kprobe hooks"
---

The first use case is file access, which can be observed with the Tetragon
`process_kprobe` JSON events. By using kprobe hook points, these events are
able to observe arbitrary kernel calls and file descriptors in the Linux
kernel, giving you the ability to monitor every file a process opens, reads,
writes, and closes throughout its lifecycle.

In this example, we can monitor if a process inside a Kubernetes workload performs
an open, close, read or write in the `/etc/` directory. The policy may further
specify additional directories or specific files if needed.

As a first step, let's apply the following `TracingPolicy`:

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/sys_write_follow_fd_prefix.yaml
```

As a second step, let's start monitoring the events from the `xwing` pod:
```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --namespace default --pod xwing
```

In another terminal, `kubectl exec` into the `xwing` pod:
```bash
kubectl exec -it xwing -- /bin/bash
```
and edit the `/etc/passwd` file:
```bash
vi /etc/passwd
```

If you observe, the output in the first terminal should be:
```bash
🚀 process default/xwing /usr/bin/vi /etc/passwd
📬 open    default/xwing /usr/bin/vi /etc/passwd
📚 read    default/xwing /usr/bin/vi /etc/passwd 1269 bytes
📪 close   default/xwing /usr/bin/vi /etc/passwd
📬 open    default/xwing /usr/bin/vi /etc/passwd
📝 write   default/xwing /usr/bin/vi /etc/passwd 1277 bytes
💥 exit    default/xwing /usr/bin/vi /etc/passwd 0
```

Note, that open and close are only generated for `/etc/` files because of eBPF in kernel
filtering. The default CRD additionally filters events associated with the
pod init process to filter init noise from pod start.

Similarly to the previous example, reviewing the JSON events provides
additional data. An example `process_kprobe` event observing a write can be:

<details><summary> Process Kprobe Event </summary>
<p>

```json
{
   "process_kprobe":{
      "process":{
         "exec_id":"a2luZC1jb250cm9sLXBsYW5lOjE1MDA0MzM3MDE1MDI6MTkxNjM=",
         "pid":19163,
         "uid":0,
         "cwd":"/",
         "binary":"/usr/bin/vi",
         "arguments":"/etc/passwd",
         "flags":"execve rootcwd clone",
         "start_time":"2022-05-26T22:05:13.894Z",
         "auid":4294967295,
         "pod":{
            "namespace":"default",
            "name":"xwing",
            "container":{
               "id":"containerd://4b0df5a137260a6b95cbf6443bb2f4b0c9309e6ccb3d8afdbc3da8fff40c0778",
               "name":"spaceship",
               "image":{
                  "id":"docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
                  "name":"docker.io/tgraf/netperf:latest"
               },
               "start_time":"2022-05-26T21:58:11Z",
               "pid":25
            }
         },
         "docker":"4b0df5a137260a6b95cbf6443bb2f4b",
         "parent_exec_id":"a2luZC1jb250cm9sLXBsYW5lOjEyMDQ1NTIzMTUwNjY6MTc1NDI=",
         "refcnt":1
      },
      "parent":{

      },
      "function_name":"__x64_sys_write",
      "args":[
         {
            "file_arg":{
               "path":"/etc/passwd"
            }
         },
         {
            "bytes_arg":"cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYXNoCm5hdGFsaWEKYmluOng6MToxOmJpbjovYmluOi9zYmluL25vbG9naW4KZGFlbW9uOng6MjoyOmRhZW1vbjovc2Jpbjovc2Jpbi9ub2xvZ2luCmFkbTp4OjM6NDphZG06L3Zhci9hZG06L3NiaW4vbm9sb2dpbgpscDp4OjQ6NzpscDovdmFyL3Nwb29sL2xwZDovc2Jpbi9ub2xvZ2luCnN5bmM6eDo1OjA6c3luYzovc2JpbjovYmluL3N5bmMKc2h1dGRvd246eDo2OjA6c2h1dGRvd246L3NiaW46L3NiaW4vc2h1dGRvd24KaGFsdDp4Ojc6MDpoYWx0Oi9zYmluOi9zYmluL2hhbHQKbWFpbDp4Ojg6MTI6bWFpbDovdmFyL3Nwb29sL21haWw6L3NiaW4vbm9sb2dpbgpuZXdzOng6OToxMzpuZXdzOi91c3IvbGliL25ld3M6L3NiaW4vbm9sb2dpbgp1dWNwOng6MTA6MTQ6dXVjcDovdmFyL3Nwb29sL3V1Y3BwdWJsaWM6L3NiaW4vbm9sb2dpbgpvcGVyYXRvcjp4OjExOjA6b3BlcmF0b3I6L3Jvb3Q6L2Jpbi9zaAptYW46eDoxMzoxNTptYW46L3Vzci9tYW46L3NiaW4vbm9sb2dpbgpwb3N0bWFzdGVyOng6MTQ6MTI6cG9zdG1hc3RlcjovdmFyL3Nwb29sL21haWw6L3NiaW4vbm9sb2dpbgpjcm9uOng6MTY6MTY6Y3JvbjovdmFyL3Nwb29sL2Nyb246L3NiaW4vbm9sb2dpbgpmdHA6eDoyMToyMTo6L3Zhci9saWIvZnRwOi9zYmluL25vbG9naW4Kc3NoZDp4OjIyOjIyOnNzaGQ6L2Rldi9udWxsOi9zYmluL25vbG9naW4KYXQ6eDoyNToyNTphdDovdmFyL3Nwb29sL2Nyb24vYXRqb2JzOi9zYmluL25vbG9naW4Kc3F1aWQ6eDozMTozMTpTcXVpZDovdmFyL2NhY2hlL3NxdWlkOi9zYmluL25vbG9naW4KeGZzOng6MzM6MzM6WCBGb250IFNlcnZlcjovZXRjL1gxMS9mczovc2Jpbi9ub2xvZ2luCmdhbWVzOng6MzU6MzU6Z2FtZXM6L3Vzci9nYW1lczovc2Jpbi9ub2xvZ2luCnBvc3RncmVzOng6NzA6NzA6Oi92YXIvbGliL3Bvc3RncmVzcWw6L2Jpbi9zaApudXQ6eDo4NDo4NDpudXQ6L3Zhci9zdGF0ZS9udXQ6L3NiaW4vbm9sb2dpbgpjeXJ1czp4Ojg1OjEyOjovdXNyL2N5cnVzOi9zYmluL25vbG9naW4KdnBvcG1haWw6eDo4OTo4OTo6L3Zhci92cG9wbWFpbDovc2Jpbi9ub2xvZ2luCm50cDp4OjEyMzoxMjM6TlRQOi92YXIvZW1wdHk6L3NiaW4vbm9sb2dpbgpzbW1zcDp4OjIwOToyMDk6c21tc3A6L3Zhci9zcG9vbC9tcXVldWU6L3NiaW4vbm9sb2dpbgpndWVzdDp4OjQwNToxMDA6Z3Vlc3Q6L2Rldi9udWxsOi9zYmluL25vbG9naW4Kbm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi86L3NiaW4vbm9sb2dpbgo="
         },
         {
            "size_arg":"1277"
         }
      ],
      "action":"KPROBE_ACTION_POST"
   },
   "node_name":"kind-control-plane",
   "time":"2022-05-26T22:05:25.962Z"
}
```

</p></details>

In addition to the Kubernetes Identity
and process metadata from exec events, `process_kprobe` events contain
the arguments of the observed system call. In the above case they are

* `path`: the observed file path
* `bytes_arg`: content of the observed file encoded in base64
* `size_arg`: size of the observed file in bytes

To disable the `TracingPolicy` run:

```bash
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/sys_write_follow_fd_prefix.yaml
```

