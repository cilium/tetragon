---
title: "Deploy with a package"
linkTitle: "Package"
icon: "tutorials"
weight: 3
description: "Install and manage Tetragon via released packages."
---

## Install

Tetragon will be managed as a systemd service. Tarballs are built and
distributed along the assets in [the releases](https://github.com/cilium/tetragon/releases).

{{< note >}}
The binary tarball only supports amd64 for now.
{{< /note >}}

1. First download the latest binary tarball, using `curl` for example:

   ```shell
   curl -LO https://github.com/cilium/tetragon/releases/download/{{< latest-version >}}/tetragon-{{< latest-version >}}-amd64.tar.gz
   ```

2. Extract the downloaded archive, and start the install script to install
   Tetragon. Feel free to inspect the script before starting it.

   ```shell
   tar -xvf tetragon-{{< latest-version >}}-amd64.tar.gz
   cd tetragon-{{< latest-version >}}-amd64/
   sudo ./install.sh
   ```

   If Tetragon was successfully installed, the final output should be similar to:

   ```
   Tetragon installed successfully!
   ```

3. Finally, you can check the Tetragon systemd service.

   ```shell
   sudo systemctl status tetragon
   ```

   The output should be similar to:

   ```
   ● tetragon.service - Tetragon eBPF-based Security Observability and Runtime Enforcement
    Loaded: loaded (/lib/systemd/system/tetragon.service; enabled; vendor preset: enabled)
    Active: active (running) since Mon 2023-01-23 20:08:16 CET; 5s ago
      Docs: https://github.com/cilium/tetragon/
   Main PID: 138819 (tetragon)
     Tasks: 17 (limit: 18985)
    Memory: 151.7M
       CPU: 913ms
    CGroup: /system.slice/tetragon.service
            └─138819 /usr/local/bin/tetragon
   ```

{{< note >}}
If Tetragon does not to start due to BTF issues, please refer to the
[corresponding question in the FAQ]({{< ref "/docs/faq/#tetragon-failed-to-start-complaining-about-a-missing-btf-file" >}})
for details and solutions.
{{< /note >}}

## Configuration

The default Tetragon configuration shipped with the Tetragon package will be
installed in `/usr/local/lib/tetragon/tetragon.conf.d/`. Local administrators
can change the configuration by adding drop-ins inside
`/etc/tetragon/tetragon.conf.d/` to override the default settings or use the
command line flags. To restore default settings, remove any added configuration
inside `/etc/tetragon/tetragon.conf.d/`.

See [Tetragon daemon configuration](/docs/reference/tetragon-configuration) for further details.

## Upgrade

To upgrade Tetragon:

1. Download the new tarball.

   ```shell
   curl -LO https://github.com/cilium/tetragon/releases/download/{{< latest-version >}}/tetragon-{{< latest-version >}}-amd64.tar.gz
   ```

2. Stop the Tetragon service.

   ```shell
   sudo systemctl stop tetragon
   ```

3. Remove the old Tetragon version.

   ```shell
   sudo rm -fr /usr/lib/systemd/system/tetragon.service
   sudo rm -fr /usr/local/bin/tetragon
   sudo rm -fr /usr/local/lib/tetragon/
   ```

4. Install the upgraded Tetragon version.

   ```shell
   tar -xvf tetragon-{{< latest-version >}}-amd64.tar.gz
   cd tetragon-{{< latest-version >}}-amd64/
   sudo ./install.sh
   ```

## Uninstall

To completely remove Tetragon run the `uninstall.sh` script that is provided
inside the tarball.

```shell
sudo ./uninstall.sh
```

Or remove it manually.

```shell
sudo systemctl stop tetragon
sudo systemctl disable tetragon
sudo rm -fr /usr/lib/systemd/system/tetragon.service
sudo systemctl daemon-reload
sudo rm -fr /usr/local/bin/tetragon
sudo rm -fr /usr/local/bin/tetra
sudo rm -fr /usr/local/lib/tetragon/
```

To just purge custom settings:

```shell
sudo rm -fr /etc/tetragon/
```

## Operating

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

### Tetragon Events

By default JSON events are logged to `/var/log/tetragon/tetragon.log` unless this location is changed.
Logs are always rotated into the same directory.

To read real-time JSON events, tailing the logs file is enough.

   ```shell
   sudo tail -f /var/log/tetragon/tetragon.log
   ```

Tetragon also ships a gRPC client that can be used to receive events.

1. To print events in `json` format using `tetra` gRPC client:
   ```shell
   sudo tetra --server-address "unix:///var/run/tetragon/tetragon.sock" getevents
   ```

2. To print events in human compact format:
   ```shell
   sudo tetra --server-address "unix:///var/run/tetragon/tetragon.sock" getevents -o compact
   ```

## What's next

See [Explore security observability events](/docs/getting-started/explore-security-observability-events/)
to learn more about how to see the Tetragon events.

