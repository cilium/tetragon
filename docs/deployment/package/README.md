# Package Deployment

This document will guide you through installing Tetragon on your Linux host machines.

## Requirement

### BTF

Many common Linux distributions now ship with BTF enabled and do not require
any extra work. To check if BTF is enabled on your Linux system, the standard
location is:

```
$ ls /sys/kernel/btf/
```

### systemd

Tetragon will be managed as a systemd service.

## Configuration

Default configurations are shipped with Tetragon packages that local administrators
can override by using their own configurations inside `/etc/tetragon/` directory.

To read more about how configurations are handled please check [Tetragon Configuration doc](../../configuration/README.md).


## Linux Binary Tarball

### Stable versions

TODO complete.

### Unstable Development versions

TODO complete.

### Install

1. Download the latest binary tarball

   TODO complete.

2. Install Tetragon

   ```bash
   tar -xvf tetragon-v0.8.3-amd64.tar.gz
   cd tetragon-v0.8.3-amd64/
   sudo ./install.sh
   ```

3. Check Tetragon service

   ```bash
   sudo systemctl status tetragon
   ```

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

### Update

To update Tetragon:

1. Download new tarball

   TODO complete.

2. Stop Tetragon service

   ```bash
   sudo systemctl stop tetragon
   ```

3. Remove old Tetragon version

   ```bash
   sudo rm -fr /usr/lib/systemd/system/tetragon.service
   sudo rm -fr /usr/local/bin/tetragon
   sudo rm -fr /usr/local/lib/tetragon/
   ```

4. Install new Tetragon version

   ```bash
   tar -xvf tetragon-v0.8.4-amd64.tar.gz
   cd tetragon-v0.8.4-amd64/
   sudo ./install.sh
   ```

### Configure

By default Tetragon configuration will be installed in
`/usr/local/lib/tetragon/tetragon.conf.d/`.

If you want to change the configuration, then add your drop-ins inside `/etc/tetragon/tetragon.conf.d/` to override the default
settings. For further details and examples, please check [Tetragon Configuration doc](../../configuration/README.md).

To restore default settings, remove any added configuration inside
`/etc/tetragon/`.


### Remove

To remove Tetragon:

   ```bash
   sudo systemctl stop tetragon
   sudo systemctl disable tetragon
   sudo rm -fr /usr/lib/systemd/system/tetragon.service
   sudo systemctl daemon-reload
   sudo rm -fr /usr/local/bin/tetragon
   sudo rm -fr /usr/local/bin/tetra
   sudo rm -fr /usr/local/lib/tetragon/
   ```

Or run the `uninstall.sh` script that is provided inside the tarball.

   ```bash
   sudo ./uninstall.sh
   ```

To remove custom settings:

   ```bash
   sudo rm -fr /etc/tetragon/
   ```


## Tetragon Events

By default JSON events are logged to `/var/log/tetragon/tetragon.log` unless this location is changed.
Logs are always rotated into the same directory.

To read real-time JSON events, tailing the logs file is enough.

   ```bash
   sudo tail -f /var/log/tetragon/tetragon.log
   ```

Tetragon also ships a GRPC client that can be used to receive events.

1. To print events in `json` format using `tetra` GRPC client:
   ```
   sudo tetra --server-address "unix:///var/run/tetragon/tetragon.sock" getevents
   ```

2. To print events in human compact format:
   ```
   sudo tetra --server-address "unix:///var/run/tetragon/tetragon.sock" getevents -o compact
   ```
