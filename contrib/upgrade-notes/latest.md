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

### Events (protobuf API)

* TBD

### Metrics

* TBD
