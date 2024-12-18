---
title: "Log level"
weight: 2
description: "Learn how to configure log levels."
---

When debugging, it might be useful to change the log level. The default log
level is controlled by the log-level option at startup:

* Enable debug level with `--log-level=debug`
* Enable trace level with `--log-level=trace`

## Change log level on Kubernetes

{{< warning >}}
The Pods of the Tetragon DaemonSet will be restarted automatically after
changing the debug Helm value.
{{< /warning >}}

It is possible to change the log level of Tetragon's DaemonSet Pods by setting
`tetragon.debug` to `true`.

## Change log level dynamically

It is possible to change the log level dynamically by using the `tetra loglevel`
sub-command. `tetra` needs access to Tetragon's gRPC server endpoint which can
be configured via `--server-address`.

{{< warning >}}
Keep in mind that Tetragon's gRPC server is (by default) only exposed on
`localhost`. Also, it's important to understand that this only changes the log
level of the single Tetragon instance targeted with `--server-address` and not
all Tetragon instances when it's, for example, running as DaemonSet in a
Kubernetes environment.
{{< /warning >}}

* Get the current log level:

  ```shell
  tetra loglevel get
  ```

* Dynamically change the log level. Allowed values are
`[trace|debug|info|warning|error|fatal|panic]`:

  ```shell
  tetra loglevel set debug
  ```
