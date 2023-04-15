---
title: "Read Tetragon metrics"
weight: 3
description: "Learn how to read Tetragon metrics."
---

If you run Tetragon with the helm chart, it should be enabled, you can read `cat /var/run/tetragon/tetragon-info.json` for the info but typically it listens on `2112`.

If you run Tetragon standalone you can use: `sudo ./tetragon --bpf-lib ./bpf/objs/ --metrics-server localhost:2112` to start with the metrics server (it's disabled by default)

Then to read the metrics you can do `curl localhost:2112/metrics`.

