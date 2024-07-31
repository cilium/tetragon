---
title: "Event throttling"
weight: 5
description: "Monitor and throttle cgroup events rate"
---

This page shows you how to configure per-cgroup rate monitoring.


## Concept

The idea is that tetragon monitors events rate per cgroup and throttle
them (stops posting its events) if they cross configured threshold.

The throttled cgroup is monitored and if its traffic gets stable under
the limit again, it stops the cgroup throttling and tetragon resumes
receiving the cgroup's events.

The throttle action generates following events:

- `THROTTLE` start event is sent when the group rate limit is crossed
- `THROTTLE` stop event is sent when the cgroup rate is again below the limit stable for 5 seconds

{{< note >}}
The threshold for given cgroup is monitored *per CPU*.
When the events are spread around on multiple CPUs we will throttle
them per CPU only if they cross the threshold on that CPU.
{{< /note >}}

{{< note >}}
At the moment we monitor and limit base sensor events:
  - `PROCESS_EXEC`
  - `PROCESS_EXIT`
{{< /note >}}

## Setup

The cgroup rate is configured with `--cgroup-rate` option:

```
--cgroup-rate string
  Base sensor events cgroup rate <events,interval> disabled by default
  ('1000,1s' means rate 1000 events per second)
```

- `--cgroup-rate=10,1s`

   sets the cgroup threshold on 10 events per 1 second

- `--cgroup-rate=1000,1s`

   sets the cgroup threshold on 1000 events per 1 second

- `--cgroup-rate=100,1m`

    sets the cgroup threshold on 1000 events per 1 minutes

- `--cgroup-rate=10000,10m`

    sets the cgroup threshold on 1000 events per 10 minutes


## Events

The throttle events contains fields as follows.

- `THROTTLE_START`

  ```json
  {
    "process_throttle": {
      "type": "THROTTLE_START",
      "cgroup": "session-429.scope"
    },
    "node_name": "ubuntu-22",
    "time": "2024-07-26T13:07:43.178407128Z"
  }
  ```

- `THROTTLE_STOP`

  ```json
  {
    "process_throttle": {
      "type": "THROTTLE_STOP",
      "cgroup": "session-429.scope"
    },
    "node_name": "ubuntu-22",
    "time": "2024-07-26T13:07:55.501718877Z"
  }
  ```


## Example

This example shows how to generate throttle events when cgroup rate monitoring is enabled.

1. Start tetragon with cgroup rate monitoring 10 events per second.

   ```shell
   tetragon --bpf-lib ./bpf/objs/ --cgroup-rate=10,1s
   ```

   The successful configuration will show in tetragon log.

   ```
   ...
   time="2024-07-26T13:33:19Z" level=info msg="Cgroup rate started (10/1s)"
   ...
   ```

1. Spawn more than 10 events per second.

   ```shell
   while :; do sleep 0.001s; done
   ```

1. Monitor events shows throttling.


   ```shell
   tetra getevents -o compact
   ```

   The output should be similar to:

   ```
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   🧬 throttle START session-429.scope
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s
   💥 exit    ubuntu-22 /usr/bin/sleep 0.001s 0
   🚀 process ubuntu-22 /usr/bin/sleep 0.001s

   🧬 throttle STOP  session-429.scope
   ```

   When you stop the while loop from the other terminal you will get above
   `throttle STOP` event after 5 seconds.


##  Limitations

- The cgroup rate is monitored per CPU
- At the moment we only monitor and limit base sensor and kprobe events:
  - `PROCESS_EXEC`
  - `PROCESS_EXIT`

