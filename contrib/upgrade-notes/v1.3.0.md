## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* Behavior of `export-file-perm` flag (and corresponding Helm value `tetragon.exportFilePerm`) changed. In case the export file exists, but has different permissions than specified in the option, Tetragon will change the file permissions on the next log rotation. In older versions, log rotation preserved permissions of the existing file. Before upgrading check if permissions of the existing export file match the option (600 by default), and set the agent flag or Helm value to the desired value if needed.

### Agent Options

* TBD

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)


#### New events for `syscall64` type

Previous versions of Tetragon did not distinguish between different ABIs when using the syscall64 type
because the output was just a `size_arg` with the id. When executing the `getcpu` syscall, for example, the JSON
for 64- and 32-bits would be:
```
"args":[{"size_arg":"309"}]
"args":[{"size_arg":"318"}]
```

Note that id 318 for `x86_64` is a different syscall: `getrandom` so we cannot distinguish between a `getrandom` syscall on x86_64
and a `getcpu` call on 32-bit (`i386`). To address this issue, the output of `syscall64` was changed to a `SyscallId` object that
also includes the ABI. So the JSON for 64- and 32-bits `getcpu` now is:

```
"args":[{"syscall_id":{"id":309,"abi":"x64"}}]
"args":[{"syscall_id":{"id":318,"abi":"i386"}}]
```

Users that want to maintain the old behavior can use the `--enable-compatibility-syscall64-size-type` flag for this version.
The flag will be removed in v1.4.

### Metrics

* `tetragon_ratelimit_dropped_total` metric is renamed to `tetragon_export_ratelimit_events_dropped_total`
