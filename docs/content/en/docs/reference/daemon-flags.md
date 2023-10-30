```
Tetragon - eBPF-based Security Observability and Runtime Enforcement

Usage:
  tetragon [flags]

Flags:
      --bpf-lib string                            Location of Tetragon libs (btf and bpf files) (default "/var/lib/tetragon/")
      --btf string                                Location of btf
      --config-dir string                         Configuration directory that contains a file for each option
      --data-cache-size int                       Size of the data events cache (default 1024)
  -d, --debug                                     Enable debug messages. Equivalent to '--log-level=debug'
      --disable-kprobe-multi                      Allow to disable kprobe multi interface
      --enable-export-aggregation                 Enable JSON export aggregation
      --enable-k8s-api                            Access Kubernetes API to associate Tetragon events with Kubernetes pods
      --enable-msg-handling-latency               Enable metrics for message handling latency
      --enable-pid-set-filter                     Enable pidSet export filters. Not recommended for production use
      --enable-pod-info                           Enable PodInfo custom resource
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
      --export-file-perm string                   Access permissions on JSON export files (default "600")
      --export-file-rotation-interval duration    Interval at which to rotate JSON export files in addition to rotating them by size
      --export-filename string                    Filename for JSON export. Disabled by default
      --export-rate-limit int                     Rate limit (per minute) for event export. Set to -1 to disable (default -1)
      --expose-kernel-addresses                   Expose real kernel addresses in events stack traces
      --field-filters string                      Field filters for event exports
      --force-large-progs                         Force loading large programs, even in kernels with < 5.3 versions
      --force-small-progs                         Force loading small programs, even in kernels with >= 5.3 versions
      --gops-address string                       gops server address (e.g. 'localhost:8118'). Disabled by default
  -h, --help                                      help for tetragon
      --k8s-kubeconfig-path string                Absolute path of the kubernetes kubeconfig file
      --kernel string                             Kernel version
      --kmods strings                             List of kernel modules to load symbols from
      --log-format string                         Set log format (default "text")
      --log-level string                          Set log level (default "info")
      --metrics-label-filter string               Comma-separated list of enabled metric labels. (e.g. "namespace,workload,pod,binary") By default all labels are enabled.
      --metrics-server string                     Metrics server address (e.g. ':2112'). Disabled by default
      --netns-dir string                          Network namespace dir (default "/var/run/docker/netns/")
      --process-cache-size int                    Size of the process cache (default 65536)
      --procfs string                             Location of procfs to consume existing PIDs (default "/proc/")
      --rb-queue-size string                      Set size of channel between ring buffer and sensor go routines (default 65k, allows K/M/G suffix) (default "65535")
      --rb-size string                            Set perf ring buffer size for single cpu (default 65k, allows K/M/G suffix) (default "0")
      --rb-size-total string                      Set perf ring buffer size in total for all cpus (default 65k per cpu, allows K/M/G suffix) (default "0")
      --release-pinned-bpf                        Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable (default true)
      --server-address string                     gRPC server address (e.g. 'localhost:54321' or 'unix:///var/run/tetragon/tetragon.sock' (default "localhost:54321")
      --tracing-policy string                     Tracing policy file to load at startup
      --tracing-policy-dir string                 Directory from where to load Tracing Policies (default "/etc/tetragon/tetragon.tp.d")
      --verbose int                               set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump
```
