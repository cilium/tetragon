---
title: "BPF programs statistics"
weight: 3
description: "Monitor BPF programs statistics"
aliases: ["/docs/concepts/performance-stats"]
---

This page shows you how to monitor BPF programs statistics.

## Concept

The BPF subsystem provides performance data for each loaded program and tetragon
exports that in metrics or display that in terminal in top like tool.

## In terminal

The tetra command allows to display loaded BPF programs in terminal with:

```shell
tetra debug progs
```

The default output shows tetragon programs only and looks like:

```
2024-10-31 11:12:45.94715546 +0000 UTC m=+8.038098448

Ovh(%)  Id      Cnt     Time    Name                            Pin
  0.00  22201   0       0       event_execve                    /sys/fs/bpf/tetragon/__base__/event_execve/prog
  0.00  22198   0       0       event_exit_acct_process         /sys/fs/bpf/tetragon/__base__/event_exit/prog
  0.00  22200   0       0       event_wake_up_new_task          /sys/fs/bpf/tetragon/__base__/kprobe_pid_clear/prog
  0.00  22207   0       0       tg_cgroup_rmdir                 /sys/fs/bpf/tetragon/__base__/tg_cgroup_rmdir/prog
  0.00  22206   0       0       tg_kp_bprm_committing_creds     /sys/fs/bpf/tetragon/__base__/tg_kp_bprm_committing_creds/prog
  0.00  22221   0       0       generic_kprobe_event            /sys/fs/bpf/tetragon/syswritefollowfdpsswd/generic_kprobe/__x64_sys_close/prog
  0.00  22225   0       0       generic_kprobe_event            /sys/fs/bpf/tetragon/syswritefollowfdpsswd/generic_kprobe/__x64_sys_write/prog
  0.00  22211   0       0       generic_kprobe_event            /sys/fs/bpf/tetragon/syswritefollowfdpsswd/generic_kprobe/fd_install/prog
```

The fields have following meaning:

- `Ovh` is system wide overhead of the BPF program
- `Id` is global BPF ID of the program (as shown by `bpftool prog`)
- `Cnt` is count with number of BPF program executions
- `Time` is sum of the time of all BPF program executions
- `Pin` is BPF program pin path in bpfffs

It's possible to display all BPF programs with `--all`:

```shell
tetra debug progs --all
```

That has following output:

```
2024-10-31 11:19:37.720137195 +0000 UTC m=+7.165535117

Ovh(%)  Id      Cnt     Time    Name            Pin
  0.00  159     2       82620   event_execve    -
  0.00  171     68      18564   iter            -
  0.00  158     2       10170   event_wake_up_n -
  0.00  164     2       4254    tg_kp_bprm_comm -
  0.00  157     2       3868    event_exit_acct -
  0.00  97      2       1680                    -
  0.00  35      2       1442                    -
  0.00  83      0       0       sd_devices      -
  0.00  9       0       0                       -
  0.00  7       0       0                       -
  0.00  8       0       0                       -
  0.00  87      0       0       sd_devices      -
...
```

The bpffs mount and iterator object path are auto detected by default, but
it's possible to override them with --bpf-lib and and --bpf-lib options, like:

```shell
kubectl exec -ti -n kube-system tetragon-66rk4 -c tetragon -- tetra debug progs --bpf-dir /run/cilium/bpffs/tetragon/ --all --bpf-lib /var/lib/tetragon/
```

Note that there are other options to customize the behaviour:

```shell
tetra debug progs --help
```
```
Retrieve information about BPF programs on the host.

Examples:
- tetragon BPF programs top style
  # tetra debug progs
- all BPF programs top style
  # tetra debug progs --all
- one shot mode (displays one interval data)
  # tetra debug progs --once
- change interval to 10 seconds
  # tetra debug progs  --timeout 10
- change interval to 10 seconds in one shot mode
  # tetra debug progs --once --timeout 10

Usage:
  tetra debug progs [flags]

Aliases:
  progs, top

Flags:
      --all              Get all programs
      --bpf-dir string   Location of bpffs tetragon directory (auto detect by default)
      --bpf-lib string   Location of Tetragon libs, btf and bpf files (auto detect by default)
  -h, --help             help for progs
      --no-clear         Do not clear screen between rounds
      --once             Run in one shot mode
      --timeout int      Interval in seconds (delay in one shot mode) (default 1)
```

## Metrics

The BPF subsystem provides performance data for each loaded program
and tetragon exports that in metrics.

For each loaded BPF program we get:
- `run count` which counts how many times the BPF program was executed
- `run time` which sums the time BPF program spent in all its executions


Hence for each loaded BPF program we export 2 related metrics:

- `tetragon_overhead_time_program_total[namespace,policy,sensor,attach]`
- `tetragon_overhead_cnt_program_total[namespace,policy,sensor,attach]`


Each loaded program is identified by labels:

- `namespace` is policy Kubernetes namespace
- `policy` is policy name
- `sensor` is sensor name
- `attach` is program attachment name


If we have `generic_kprobe` sensor attached on `__x64_sys_close` kernel function
under `syswritefollowfdpsswd` policy, the related metrics will look like:

```
tetragon_overhead_program_runs_total{attach="__x64_sys_close",policy="syswritefollowfdpsswd",policy_namespace="",sensor="generic_kprobe"} 15894
tetragon_overhead_program_seconds_total{attach="__x64_sys_close",policy="syswritefollowfdpsswd",policy_namespace="",sensor="generic_kprobe"} 1.03908217e+08
```


##  Limitations

Note that the BPF programs statistics are not enabled by default, because they introduce extra overhead,
so it's necessary to enable them manually.

- Either with `sysctl`:

  ```shell
  sysctl kernel.bpf_stats_enabled=1
  ```

  and make sure you disable the stats when it's no longer needed:

  ```shell
  sysctl kernel.bpf_stats_enabled=0
  ```

- Or with following `tetra` command:

  ```shell
  tetra debug enable-stats
  ^C
  ```

  where the stats are enabled as long as the command is running (sleeping really).
