---
title: "Explore Security Observability Events"
weight: 5
icon: "reference"
description: "Learn how to start exploring the Tetragon events"
---

There are two ways to quicly observer Tetragon events, either the raw JSON output from
Tetragon logs directly, or using the [`tetra`](https://github.com/cilium/tetragon/tree/main/cmd/tetra)
client CLI to pretty print events, filter by process, pod, and other fields.

The `tetra` client CLI is particulary useful to interact with Tetragon from the host
without entering the container, from a remote host, a macOS or a Windows system. Fo such
cases please follow the [Install tetra CLI](/docs/getting-started/install-tetra-cli) guide
before continuing.

This guide is splitted by deployment methods since every deployment can have its own way
on how to explore the raw JSON logs.

## Kubernetes deployment

After Tetragon and the [demo application is up and
running](/docs/getting-started/kubernetes-quickstart-guide/#deploy-the-demo-application)
you can examine the security and observability events produced by Tetragon in
different ways.

Tetragon by default monitors [Process lifecycle](/docs/use-cases/process-lifecycle) which
can be observed with the Tetragon [`process_exec`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexec) and [  `process_exit`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexit) JSON events.
These events contain the full lifecycle of processes, from fork/exec to
exit, including metadata such as:

* Binary name: Defines the name of an executable file
* Parent process: Helps to identify process execution anomalies (e.g., if a nodejs app forks a shell, this is suspicious)
* Command-line argument: Defines the program runtime behavior
* Current working directory: Helps to identify hidden malware execution from a temporary folder, which is a common pattern used in malwares
* Kubernetes metadata: Contains pods, labels, and Kubernetes namespaces, which are critical to identify service owners, particularly in a multitenant environments
* exec_id: A unique process identifier that correlates all recorded activity of a process


In another terminal, let's `kubectl exec` into the `xwing` pod and execute some example commands:

```bash
kubectl exec -it xwing -- /bin/bash
whoami
```

### Raw JSON logs

The first way is to observe the raw json output from the stdout container log:

```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f
```

Which will inlude the following events:
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

Using the [`jq`](https://jqlang.github.io/jq/) tool it is possible to filter by the
[`process_exec`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexec) and [`process_exit`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexit) events from the `xwing` pod:
```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | jq 'select(.process_exec.process.pod.name=="xwing" or .process_exit.process.pod.name=="xwing")'
```

### `tetra` CLI

The `tetra` CLI is already available inside `tetragon` container.

To see events in compact format use the following command:

```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

To filter events by the `xwing` pod use the following command:
```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --namespace default --pod xwing
```

These will produce the following events:
```bash
🚀 process default/xwing /bin/bash
🚀 process default/xwing /usr/bin/whoami
💥 exit    default/xwing /usr/bin/whoami 0
```

Here you can see the binary names along with its arguments, the pod info, and
return codes in a compact one-line view of the events.

It is also possible to explore events without entering the `tetragon` container, by [installing `tetra` CLI](/docs/getting-started/install-tetra-cli).

1. Pretty print `tetragon` JSON raw output:

   ```bash
   kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact
   ```

2. Pretty print `tetragon` JSON raw output and filter by `xwing` pod events:

   ```bash
   kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --namespace default --pod xwing
   ```

## Container deployment

If Tetragon was deployed as a [Container](/docs/getting-started/deployment/container) without a Kubernetes cluster, then
to see the events, you can use the `tetra` CLI already shipped in the
Tetragon container. It will connect to the Tetragon gRPC server and displays the
events.

### Raw JSON logs

To export the raw json events to log files, you have to start Tetragon with the `--export-filename`
controlling setting. For container deployments you can set this setting using one
of the following methodes:

* As an environment variable, add the `--env "TETRAGON_EXPORT_FILENAME=/var/log/tetragon/tetragon.log"`:

    ```bash
    docker run --name tetragon --rm -d                   \
    --pid=host --cgroupns=host --privileged          \
    --env "TETRAGON_EXPORT_FILENAME=/var/log/tetragon/tetragon.log" \
    -v /sys/kernel:/sys/kernel \
    -v /etc/tetragon/:/etc/tetragon/ \
    -v /var/log/tetragon/:/var/log/tetragon/ \
    quay.io/cilium/tetragon:{{< latest-version >}}
    ```

* As a drop-in configuration file in the host `/etc/tetragon/tetragon.conf.d/export-filename` with a content that points to the log file:

    ```bash
    /var/log/tetragon/tetragon.log
    ```

    When `tetragon` container starts, it will auto read the mounted volume from the host
    `/etc/tetragon/` find the configuration directory [`/etc/tetragon/tetragon.conf.d/`](/docs/reference/tetragon-configuration/#configuration-precedence)
    and reads the [`/etc/tetragon/tetragon.conf.d/export-filename`](/docs/reference/tetragon-configuration/#configuration-examples)
    content and use it as a target path for the exported JSON logs.

    See [Tetragon daemon configuration](/docs/reference/tetragon-configuration) reference for further details.

{{< note >}}
The `-v /var/log/tetragon/:/var/log/tetragon/` exports the volume used to store logs from the
container into the host. Remove it if you want the logs to stay withing the container.

Logs are always rotated in the same directory where the exported logs are. In this example they will
be rotated inside: `/var/log/tetragon/`.
{{< /note >}}


Finally to read real-time JSON events, tailing the `/var/log/tetragon/tetragon.logs` file on the host is enough.

```bash
sudo tail -f /var/log/tetragon/tetragon.log
```

Which will inlude the following events:
```json
{
  "process_exec": {
    "process": {
      "exec_id": "OjExOTc4NjUwNjYxNTk2OjM0OTI0",
      "pid": 34924,
      "uid": 1000,
      "cwd": "/home/tetragon",
      "binary": "/usr/bin/uname",
      "arguments": "-a",
      "flags": "execve clone",
      "start_time": "2023-07-16T11:50:23.945692962Z",
      "auid": 1000,
      "parent_exec_id": "OjExOTcwMjY4NTU0MDc2OjM0OTE3",
      "tid": 34924
    },
    "parent": {
      "exec_id": "OjExOTcwMjY4NTU0MDc2OjM0OTE3",
      "pid": 34917,
      "uid": 1000,
      "cwd": "/home/tetragon",
      "binary": "/usr/bin/sh",
      "flags": "execve clone",
      "start_time": "2023-07-16T11:50:15.563585160Z",
      "auid": 1000,
      "parent_exec_id": "OjIzODg3NDAwMDAwMDA6MTIzNDU=",
      "refcnt": 3,
      "tid": 34917
    }
  },
  "time": "2023-07-16T11:50:23.945692004Z"
}
```

```json
{
  "process_exit": {
    "process": {
      "exec_id": "OjExOTc4NjUwNjYxNTk2OjM0OTI0",
      "pid": 34924,
      "uid": 1000,
      "cwd": "/home/tetragon",
      "binary": "/usr/bin/uname",
      "arguments": "-a",
      "flags": "execve clone",
      "start_time": "2023-07-16T11:50:23.945692962Z",
      "auid": 1000,
      "parent_exec_id": "OjExOTcwMjY4NTU0MDc2OjM0OTE3",
      "tid": 34924
    },
    "parent": {
      "exec_id": "OjExOTcwMjY4NTU0MDc2OjM0OTE3",
      "pid": 34917,
      "uid": 1000,
      "cwd": "/home/tetragon",
      "binary": "/usr/bin/sh",
      "flags": "execve clone",
      "start_time": "2023-07-16T11:50:15.563585160Z",
      "auid": 1000,
      "parent_exec_id": "OjIzODg3NDAwMDAwMDA6MTIzNDU=",
      "refcnt": 1,
      "tid": 34917
    },
    "time": "2023-07-16T11:50:23.947280103Z"
  },
  "time": "2023-07-16T11:50:23.947278623Z"
}
```

### `tetra` CLI

After starting the `tetragon` container, type the following command to observe events:
```bash
docker exec tetragon tetra getevents -o compact
```

Then in a different terminal, you can start a shell like `sh` and start executing
programs. Here, the commands executed in the shell where `ls`, `uname -a`,
`whoami`, and `exit`, the output of `tetra` CLI should be similar to this:

```bash
🚀 process  /usr/bin/sh
🚀 process  /usr/bin/ls
💥 exit     /usr/bin/ls  0
🚀 process  /usr/bin/uname -a
💥 exit     /usr/bin/uname -a 0
🚀 process  /usr/bin/whoami
💥 exit     /usr/bin/whoami  0
💥 exit     /usr/bin/sh  0
```

You can see the start of `sh` first, then the execution of the multiple
programs, `ls`, `uname` and `whoami`, and finally the exit of `sh`.

{{< note >}}
Since Tetragon monitors all processes on the host, you may observe events
unrelated to what was typed in the shell session. Indeed, Tetragon is
monitoring every process start and exit in your environment.
{{< /note >}}
