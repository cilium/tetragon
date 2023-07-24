---
title: "Tetragon Daemon Configuration"
linkTitle: "Tetragon Daemon Configuration"
description: "Configure Tetragon daemon"
---

Tetragon default controlling settings are set during compilation, so configuration
is only needed when it is necessary to deviate from those defaults. This
document lists those controlling settings and how they can be set
as a CLI arguments or as configuration options from [YAML](https://yaml.org) files.

## Tetragon Controlling Settings

Tetragon CLI arguments:
```bash
Tetragon - eBPF-based Security Observability and Runtime Enforcement

Usage:
  tetragon [flags]

Flags:
      --bpf-lib string                            Location of Tetragon libs (btf and bpf files) (default "/var/lib/tetragon/")
      --btf string                                Location of btf
      --cilium-bpf string                         Cilium BPF directory
      --config-dir string                         Configuration directory that contains a file for each option
      --data-cache-size int                       Size of the data events cache (default 1024)
  -d, --debug                                     Enable debug messages. Equivalent to '--log-level=debug'
      --disable-kprobe-multi                      Allow to disable kprobe multi interface
      --enable-cilium-api                         Access Cilium API to associate Tetragon events with Cilium endpoints and DNS cache
      --enable-export-aggregation                 Enable JSON export aggregation
      --enable-k8s-api                            Access Kubernetes API to associate Tetragon events with Kubernetes pods
      --enable-msg-handling-latency               Enable metrics for message handling latency
      --enable-pid-set-filter                     Enable pidSet export filters. Not recommended for production use
      --enable-policy-filter                      Enable policy filter code (beta)
      --enable-policy-filter-debug                Enable policy filter debug messages
      --enable-process-ancestors                  Include ancestors in process exec events (default true)
      --enable-process-cred                       Enable process_cred events
      --enable-process-ns                         Enable namespace information in process_exec and process_kprobe events
      --event-queue-size uint                     Set the size of the internal event queue. (default 10000)
      --export-aggregation-buffer-size uint       Aggregator channel buffer size (default 10000)
      --export-aggregation-window-size duration   JSON export aggregation time window (default 15s)
      --export-allowlist string                   JSON export allowlist
      --export-denylist string                    JSON export denylist
      --export-file-compress                      Compress rotated JSON export files
      --export-file-max-backups int               Number of rotated JSON export files to retain (default 5)
      --export-file-max-size-mb int               Size in MB for rotating JSON export files (default 10)
      --export-file-rotation-interval duration    Interval at which to rotate JSON export files in addition to rotating them by size
      --export-filename string                    Filename for JSON export. Disabled by default
      --export-rate-limit int                     Rate limit (per minute) for event export. Set to -1 to disable (default -1)
      --field-filters string                      Field filters for event exports
      --force-large-progs                         Force loading large programs, even in kernels with < 5.3 versions
      --force-small-progs                         Force loading small programs, even in kernels with >= 5.3 versions
      --gops-address string                       gops server address (e.g. 'localhost:8118'). Disabled by default
  -h, --help                                      help for tetragon
      --k8s-kubeconfig-path string                Absolute path of the kubernetes kubeconfig file
      --kernel string                             Kernel version
      --log-format string                         Set log format (default "text")
      --log-level string                          Set log level (default "info")
      --metrics-server string                     Metrics server address (e.g. ':2112'). Disabled by default
      --netns-dir string                          Network namespace dir (default "/var/run/docker/netns/")
      --process-cache-size int                    Size of the process cache (default 65536)
      --procfs string                             Location of procfs to consume existing PIDs (default "/proc/")
      --rb-size int                               Set perf ring buffer size for single cpu (default 65k)
      --rb-size-total int                         Set perf ring buffer size in total for all cpus (default 65k per cpu)
      --release-pinned-bpf                        Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable (default true)
      --server-address string                     gRPC server address (e.g. 'localhost:54321' or 'unix:///var/run/tetragon/tetragon.sock' (default "localhost:54321")
      --tracing-policy string                     Tracing policy file to load at startup
      --tracing-policy-dir string                 Directory from where to load Tracing Policies (default "/etc/tetragon/tetragon.tp.d/")
      --verbose int                               set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump
```

## Configuration precedence

Tetragon controlling settings can also be loaded from [YAML](https://yaml.org/) configuration files according to this order:

1. From the drop-in configuration snippets inside the following directories
   where each filename maps to one controlling setting and the content of the
   file to its corresponding value:

   - `/usr/lib/tetragon/tetragon.conf.d/*`
   - `/usr/local/lib/tetragon/tetragon.conf.d/*`

2. From the configuration file `/etc/tetragon/tetragon.yaml` if available,
   overriding previous settings.

3. From the drop-in configuration snippets inside
   `/etc/tetragon/tetragon.conf.d/*`, similarly overriding previous settings.

4. If the `config-dir` setting is set, Tetragon loads its settings from the
   files inside the directory pointed by this option, overriding previous
   controlling settings. The `config-dir` is also part of [Kubernetes
   ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/).

When reading configuration from directories, each filename maps to one
controlling setting. If the same controlling setting is set multiple times,
then the last value or content of that file overrides the previous ones.

To summarize the configuration precedence:

1. Drop-in directory pointed by `--config-dir`.

2. Drop-in directory `/etc/tetragon/tetragon.conf.d/*`.

3. Configuration file `/etc/tetragon/tetragon.yaml`.

4. Drop-in directories:

   - `/usr/local/lib/tetragon/tetragon.conf.d/*`
   - `/usr/lib/tetragon/tetragon.conf.d/*`

{{< note >}}
To clear a controlling setting that was set before, set it again to an empty
value.

Package managers can customize the configuration by installing drop-ins under
`/usr/`. Configurations in `/etc/tetragon/` are strictly reserved for the local
administrator, who may use this logic to override package managers or the
default installed configuration.
{{< /note >}}

## Configuration examples

The [examples/configuration/tetragon.yaml](https://github.com/cilium/tetragon/blob/main/examples/configuration/tetragon.yaml)
file contains example entries showing the defaults as a guide to the
administrator. Local overrides can be created by editing and copying this file
into `/etc/tetragon/tetragon.yaml`, or by editing and copying "drop-ins" from
the [examples/configuration/tetragon.conf.d](https://github.com/cilium/tetragon/tree/main/examples/configuration/tetragon.conf.d)
directory into the `/etc/tetragon/tetragon.conf.d/` subdirectory. The latter is
generally recommended.

Each filename maps to a one controlling setting and the content of the file to
its corresponding value. This is the recommended way.

Changing configuration example:

* `/etc/tetragon/tetragon.conf.d/bpf-lib` with a corresponding value of:

   ```
   /var/lib/tetragon/
   ```

* `/etc/tetragon/tetragon.conf.d/log-format` with a corresponding value of:

   ```
   text
   ```

* `/etc/tetragon/tetragon.conf.d/export-filename` with a corresponding value of:

   ```
   /var/log/tetragon/tetragon.log
   ```

{{< note >}}
Defaults controlling settings can be restored by simply deleting `/etc/tetragon/tetragon.yaml`
and all drop-ins under `/etc/tetragon/tetragon.conf.d/`
{{< /note >}}

## Restrict gRPC API access

The gRPC API supports unix sockets, it can be set using one of the following methods:

- Use the `--server-address` flag:

   ```
   --server-address unix:///var/run/tetragon/tetragon.sock
   ```

- Or use the drop-in configuration file `/etc/tetragon/tetragon.conf.d/server-address` containing:

   ```
   unix:///var/run/tetragon/tetragon.sock
   ```

Then to access the gRPC API with `tetra` client, set `--server-address` to point to the corresponding address:

   ```
   sudo tetra --server-address unix:///var/run/tetragon/tetragon.sock getevents
   ```

{{< note >}}
When reading events with the `tetra` client, if `--server-address` is not specified,
it will try to detect if Tetragon daemon is running on the same host and use its
`server-address` configuration.
{{< /note >}}

{{< caution >}}
Ensure that you have enough privileges to open the gRPC unix socket since it is restricted to privileged users only.
{{< /caution >}}
