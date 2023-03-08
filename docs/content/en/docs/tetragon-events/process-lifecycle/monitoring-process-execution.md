---
title: "Use case: monitoring process execution"
weight: 1
description: "Monitor process lifecycle with `process_exec` and `process_exit`"
---

This first use case is monitoring process execution, which can be observed with
the Tetragon `process_exec` and `process_exit` JSON events.
These events contain the full lifecycle of processes, from fork/exec to
exit, including metadata such as:

* Binary name: Defines the name of an executable file
* Parent process: Helps to identify process execution anomalies (e.g., if a nodejs app forks a shell, this is suspicious)
* Command-line argument: Defines the program runtime behavior
* Current working directory: Helps to identify hidden malware execution from a temporary folder, which is a common pattern used in malwares
* Kubernetes metadata: Contains pods, labels, and Kubernetes namespaces, which are critical to identify service owners, particularly in a multitenant environments
* exec_id: A unique process identifier that correlates all recorded activity of a process

As a first step, let's start monitoring the events from the `xwing` pod:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --namespace default --pod xwing
```

Then in another terminal, let's `kubectl exec` into the `xwing` pod and execute
some example commands:

```bash
kubectl exec -it xwing -- /bin/bash
whoami
```

If you observe, the output in the first terminal should be:

```bash
🚀 process default/xwing /bin/bash
🚀 process default/xwing /usr/bin/whoami
💥 exit    default/xwing /usr/bin/whoami 0
```

Here you can see the binary names along with its arguments, the pod info, and
return codes in a compact one-line view of the events.

For more details use the raw JSON events to get detailed information, you can stop
the Tetragon CLI by `Crl-C` and parse the `tetragon.log` file by executing:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | jq 'select(.process_exec.process.pod.name=="xwing" or .process_exit.process.pod.name=="xwing")'
```

Example `process_exec` and `process_exit` events can be:
<details><summary> Process Exec Event </summary>
<p>

```json
{
  "process_exec": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjExNDI4NjE1NjM2OTAxOjUxNTgz",
      "pid": 51583,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/whoami",
      "arguments": "--version",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:54:45.615Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 50
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI=",
      "refcnt": 1
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI=",
      "pid": 43872,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:15:36.225Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 43
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkxODU5NTMzOTk6NDM4NjE=",
      "refcnt": 1
    }
  },
  "node_name": "kind-control-plane",
  "time": "2022-05-11T12:54:45.615Z"
}
```

</p>
</details>

<details><summary> Process Exit Event </summary>
<p>

```json
{
  "process_exit": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjExNDI4NjE1NjM2OTAxOjUxNTgz",
      "pid": 51583,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/whoami",
      "arguments": "--version",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:54:45.615Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 50
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI="
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI=",
      "pid": 43872,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:15:36.225Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 43
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkxODU5NTMzOTk6NDM4NjE="
    }
  },
  "node_name": "kind-control-plane",
  "time": "2022-05-11T12:54:45.616Z"
}
```

</p>
</details>

