# Tetragon Configuration Files

## Configuration Directories

### Synopsis

`config-dir`, `/etc/tetragon/tetragon.conf`, `/etc/tetragon/tetragon.conf.d/*`, `/usr/local/lib/tetragon/tetragon.conf.d/*`,  `/usr/lib/tetragon/tetragon.conf.d/*`


### Configuration Precedence

The default controlling settings are set during compilation, so configuration is only needed when it is necessary to deviate from those defaults.

In this case, Tetragon is able to load its controlling settings according to this order:

1. From the drop-in configuration snippets inside the following directories where each filename maps to a one option:

   `/usr/lib/tetragon/tetragon.conf.d/*`
   `/usr/local/lib/tetragon/tetragon.conf.d/*`
   `/etc/tetragon/tetragon.conf.d/*`

2. From the configuration file `/etc/tetragon/tetragon.conf` if available; overriding previous settings.

3. If the `config-dir` setting is set, Tetragon loads its settings from the files inside this directory; overriding previous settings.


When reading configuration from directories, each filename maps to a one controlling setting. If the same controlling setting is set multiple times, then the last value overrides previous ones.


So the configuration precedence is as it follows:

1. `config-dir`

2. `/etc/tetragon/tetragon.conf`

3. Drop-in directories:
   
   `/etc/tetragon/tetragon.conf.d/*`
   `/usr/local/lib/tetragon/tetragon.conf.d/*`
   `/usr/lib/tetragon/tetragon.conf.d/*`


Package managers can customize the configuration by installing drop-ins under `/usr/`. Configurations in `/etc/tetragon/` are reserved for the
local administrator, who may use this logic to override package managers or the default installed configuration.

The [tetragon.conf](./tetragon.conf) contains commented out entries showing the defaults as a guide to the administrator. Local overrides can be
created by editing and copying this file into `/etc/tetragon/tetragon.conf`, or by creating "drop-ins" in the `/etc/tetragon/tetragon.conf.d/`
subdirectory. The latter is generally recommended. Defaults can be restored by simply deleting this file and all drop-ins.
