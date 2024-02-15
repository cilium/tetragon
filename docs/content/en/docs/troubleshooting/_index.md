---
title: "Troubleshooting"
weight: 11
description: Troubleshooting Tetragon
---

## Reporting a problem

Before you report a problem, make sure to gather essential diagnostic information to streamline issue resolution. This information allows developers to investigate your problem effectively.

### Automatic log & state collection

You collect information in a Kubernetes cluster using the Cilium CLI:

```shell
cilium-cli sysdump
```

Refer to the [Cilium docs](https://docs.cilium.io/en/stable/operations/troubleshooting/#automatic-log-state-collection) for comprehensive instructions.

### Single Node Bugtool

If you are not running Kubernetes, it is also possible to run the bug collection tool manually with the scope of a single node using:

```shell
tetra bugtool
```

Tetragon's bugtool captures potentially useful information about your environment for debugging. The tool is meant to be used for debugging a single Tetragon agent node. Note in Kubernetes, the command needs to be run from inside the Tetragon pod/container.

#### Key Information Collected by the Bugtool:

- Tetragon configuration
- Network configuration
- Kernel configuration
- eBPF maps
- Process traces (if tracing is enabled)

### Running tetra bugtool Demonstrations

#### Scenario 1: Kubernetes

1. **Identify Tetragon Pod:**

```bash
kubectl get pods -n <tetragron-namespace> -l app.kubernetes.io/name=tetragon
```

2. **Execute tetra bugtool within the Pod:**

```bash
kubectl exec -n <tetragron-namespace> <tetragron-pod-name> -- tetra bugtool
```

Scenario 2: Container Installation

Enter the Tetragon Container:

Bash
docker exec -it <tetragron-container-id> /bin/sh
Use code with caution.
Run tetra bugtool:

Bash
tetra bugtool
Use code with caution.
Scenario 3: Systemd Host Installation

Execute tetra bugtool with Elevated Permissions:
Bash
sudo tetra bugtool
Use code with caution.
