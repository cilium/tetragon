---
title: "Persistent gRPC policies"
weight: 2
description: "Persist and restore tracing policies installed through gRPC"
---

Tetragon can persist tracing policies installed through the gRPC API and
restore their desired state after the agent restarts. Combined with persistent
enforcement, this allows the old BPF programs to remain active while Tetragon
loads replacement programs from the stored policies.

This feature applies only to policies installed through gRPC, including
policies added with `tetra tracingpolicy add`. Kubernetes and statically loaded
policies continue to be managed by their respective policy sources.

## Configuration

Start Tetragon with the following options:

```shell
sudo ./tetragon \
  --btf /sys/kernel/btf/vmlinux \
  --bpf-lib ./bpf/objs/ \
  --keep-sensors-on-exit \
  --release-pinned-bpf=false \
  --persist-grpc-policies \
  --persist-grpc-policies-dir /var/run/tetragon/grpc-policies
```

Use the same options each time Tetragon starts.

{{< caution >}}
`--release-pinned-bpf` defaults to `true`. Set it explicitly to `false` when
continuous enforcement across an agent restart is required. Enabling only the
policy store restores policies, but does not preserve the previous BPF tree
during startup.
{{< /caution >}}

The options have the following roles:

- `--keep-sensors-on-exit` leaves pinned sensors active when Tetragon exits.
- `--release-pinned-bpf=false` prevents Tetragon from removing the previous BPF
  tree at the beginning of startup. Tetragon moves the tree aside and removes
  it only after replacement policies have loaded.
- `--persist-grpc-policies` enables saving and restoring policies installed
  through gRPC.
- `--persist-grpc-policies-dir` selects the policy store directory. Its default
  value is `/var/run/tetragon/grpc-policies`.

## Restart sequence

On a normal restart, Tetragon performs the following handoff:

1. Rename `/sys/fs/bpf/tetragon` to `/sys/fs/bpf/tetragon_old`. The links pinned
   below this directory keep the previous BPF programs attached.
2. Create a new `/sys/fs/bpf/tetragon` tree and load the initial sensors.
3. Read and validate all records in the gRPC policy store.
4. Recreate each stored policy in the new BPF tree. Tetragon registers disabled
   policies without loading their BPF programs.
5. Remove `/sys/fs/bpf/tetragon_old`, which detaches the previous programs.

The policies are rebuilt from the persistent store; Tetragon does not reload
them from `tetragon_old`. The old BPF tree exists only to maintain coverage
during the handoff.

{{< note >}}
There is an interval during startup in which both the old and replacement
programs are attached. This avoids an enforcement gap.
{{< /note >}}

## Manage persisted policies

Policies added through gRPC are persisted automatically after they load
successfully:

```shell
sudo ./tetra tracingpolicy add policy.yaml
```

Deleting a policy removes it from both the running agent and the persistent
store:

```shell
sudo ./tetra tracingpolicy delete policy-name
```

Enable and disable operations update the stored desired state:

```shell
sudo ./tetra tracingpolicy disable policy-name
sudo ./tetra tracingpolicy enable policy-name
```

Mode changes also update the stored policy YAML:

```shell
sudo ./tetra tracingpolicy set-mode policy-name monitor
sudo ./tetra tracingpolicy set-mode policy-name enforce
```

## Stored desired state

The store uses one JSON record per policy. A policy is uniquely identified by
its domain, namespace, and name.

Each record contains:

- `yaml`: the complete policy, including its configured policy mode;
- `enabled`: whether the policy is enabled or not.

The policy identity is encoded in the record filename as
`<name>:<namespace>:<domain>.json`.

For example:

```json
{
  "yaml": "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: lsm-file-open\nspec:\n  options:\n  - name: policy-mode\n    value: monitor\n  lsmhooks:\n  - hook: file_open\n",
  "enabled": true
}
```

## Failure behavior

The running policy and its stored desired state are updated together:

- If adding a new record to the store fails, Tetragon removes the newly loaded
  runtime policy and restores any previous store state.
- Enable, disable, and mode changes write the desired state before changing the
  running policy. If the runtime change fails, Tetragon restores the previous
  record.
- Deleting a policy removes its record before deleting the running policy. If
  the runtime deletion fails, Tetragon restores the record.

At startup, Tetragon validates every stored policy before loading any of them.
If loading a policy fails, it rolls back policies restored earlier in the same
startup attempt and reports the error. The old BPF tree is removed only after
startup policy loading succeeds.
