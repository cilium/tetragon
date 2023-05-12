---
title: "Configuration"
weight: 6
description: "Tetragon configuration files and options"
---

### Synopsis

- `config-dir`
- `/etc/tetragon/tetragon.conf.d/*`
- `/etc/tetragon/tetragon.yaml`
- `/usr/local/lib/tetragon/tetragon.conf.d/*`
- `/usr/lib/tetragon/tetragon.conf.d/*`

### Configuration precedence

The default controlling settings are set during compilation, so configuration
is only needed when it is necessary to deviate from those defaults.

In this case, tetragon is able to load its controlling settings that are in
[YAML format](https://yaml.org/) according to this order:

1. From the drop-in configuration snippets inside the following directories
   where each filename maps to a one controlling setting and the content of the
   file to its corresponding value:

   `/usr/lib/tetragon/tetragon.conf.d/*`
   `/usr/local/lib/tetragon/tetragon.conf.d/*`

2. From the configuration file `/etc/tetragon/tetragon.yaml` if available;
   overriding previous settings.

3. From the drop-in configuration snippets inside
   `/etc/tetragon/tetragon.conf.d/*` directory same as 1; overriding previous
   settings.

4. If the `config-dir` setting is set, tetragon loads its settings from the
   files inside the directory pointed by this option; overriding previous
   controlling settings. The `config-dir` is also part of [Kubernetes
   ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/).

When reading configuration from directories, each filename maps to a one
controlling setting. If the same controlling setting is set multiple times,
then the last value or content of that file overrides previous ones.

To summarize the configuration precedence:

1. Drop-in directory pointed by `--config-dir`.

2. Drop-in directory `/etc/tetragon/tetragon.conf.d/*`.

3. Configuration file `/etc/tetragon/tetragon.yaml`.

4. Drop-in directories:

   `/usr/local/lib/tetragon/tetragon.conf.d/*`
   `/usr/lib/tetragon/tetragon.conf.d/*`


To clear a controlling setting that was set before, set it again to empty value.

Package managers can customize the configuration by installing drop-ins under
`/usr/`. Configurations in `/etc/tetragon/` are strictly reserved for the local
administrator, who may use this logic to override package managers or the
default installed configuration.

### What's next

The [tetragon.yaml](https://github.com/cilium/tetragon/blob/main/examples/configuration/tetragon.yaml)
contains example entries showing the defaults as a guide to the administrator.
Local overrides can be created by editing and copying this file into
`/etc/tetragon/tetragon.yaml`, or by editing and copying "drop-ins" from the
[tetragon.conf.d](https://github.com/cilium/tetragon/tree/main/examples/configuration/tetragon.conf.d)
directory into the `/etc/tetragon/tetragon.conf.d/` subdirectory. The latter is
generally recommended. Defaults can be restored by simply deleting this file
and all drop-ins.


### Restrict gRPC API access

The gRPC API supports unix sockets, it can be set using one of the following methods:

- Use the `--server-address` flag:

   ```
   --server-address unix:///var/run/tetragon/tetragon.sock
   ```

- Or use the drop-in configuration file `/etc/tetragon/tetragon.conf.d/server-address` containing:

   ```
   unix:///var/run/tetragon/tetragon.sock
   ```

{{< note >}}
Tetragon tarball by default listens to  `unix:///var/run/tetragon/tetragon.sock`
{{< /note >}}

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
