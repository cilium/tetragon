## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* CRI users: Mounting of the Container Runtime socket is moving to a directory path.
  If your systems are running Kyverno/OPA/Gatekeeper rules that allow hostPath mounts
  only by explicit paths, then you will need to extend your allowlist with the
  directory containing the socket passed to `tetragon.cri.socketHostPath`.
* `tetragon.gops.enabled` now defaults to `false`. To re-enable the gops debug
  interface, set `--set tetragon.gops.enabled=true` at install or upgrade time.
* `exportDirectory` default value has been updated to `/var/log/tetragon` from 
  `/var/run/cilium/tetragon/` to avoid writing to tmpfs.

### TracingPolicy (k8s CRD)

* `returnArgAction` no longer accepts `Post`. Use `returnArg` to include the
  return value in events, and omit `returnArgAction` for the default return-value
  behavior. Only `TrackSock` and `UntrackSock` are supported. Existing policies
  that set `returnArgAction: "Post"` should remove the field.
* `fd` type no longer needs the pre `FollowFD` and post `UnfollowFD` actions to resolve the
  path and works on its own. Existing policies that used `fd` type should be updated to remove the hooks associated with the `FollowFD` and `UnfollowFD` actions. The structure around the use of `fd` hasn't changed and no update should be necessary to the hook that used the type. 
* Actions `FollowFD`, `UnfollowFD` and `CopyFD` were removed (they were deprecated in v1.5).
* The `CelExpr` `MatchArgs` operator has been deprecated. Please use the `MatchCEL` selector instead.

### Events (protobuf API)

* TBD

### Metrics

Labels holding a message opcode are now consistently named `opcode` (the numeric
`ops.OpCode`), and every metric using one also exposes a human-readable `opstr`
label. Update any dashboards, alerts or recording rules that select on the old
label names.

* `tetragon_msg_op_total`: the `msg_op` label is renamed to `opcode`, and a new
  `opstr` label with the human-readable opcode name is added.
* `tetragon_bpf_missed_events_total`: the `msg_op` label is renamed to `opcode`,
  and a new `opstr` label with the human-readable opcode name is added.
* `tetragon_handling_latency`: the numeric opcode is now reported in a new
  `opcode` label, and the human-readable name in a new `opstr` label. The old
  `op` label is removed, so queries matching on it need updating.
* `tetragon_handler_errors_total`: a new `opstr` label with the human-readable
  opcode name is added, alongside the existing `opcode` label.
* `tetragon_data_event_size`: the `op` label is renamed to `status`. It reports
  whether handling a data event succeeded (`ok`/`bad`) and is not an opcode.
* `tetragon_events_total`: the `type` label is renamed to `event_type`, matching
  the label already used for the event type by other metrics.
