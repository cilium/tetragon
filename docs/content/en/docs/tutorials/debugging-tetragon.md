---
title: "Debugging Tetragon"
weight: 1
icon: "overview"
description: "Diagnosing Tetragon problems"
---

### Enable debug log level

When debugging, it might be useful to change the log level. The default log level is controlled by the log-level option:

* Enable debug level with `--log-level=debug`

* Enable trace level with `--log-level=trace`

### Change log level dynamically

It is possible to change the log level dynamically by sending the corresponding signal to tetragon process.

* Change log level to debug level by sending the `SIGRTMIN+20` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+20 $(pidof tetragon)
  ```

* Change log level to trace level by sending the `SIGRTMIN+21` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+21 $(pidof tetragon)
  ```

* To Restore the original log level send the `SIGRTMIN+22` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+22 $(pidof tetragon)
  ```

