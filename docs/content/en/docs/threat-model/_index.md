---
title: "Threat Model"
weight: 12
description: >
  Threat model for Tetragon
---

## Scope and Introduction

This page presents a comprehensive threat model for Tetragon, a subproject within the Cilium family. The objective of this threat model is to help users and operators understand the security implications of Tetragon’s architecture, identify potential attack vectors, and implement effective defensive controls. [Tetragon](https://tetragon.io/) is a runtime security enforcement and observability tool that utilizes eBPF to deliver deep visibility into system behavior and enforce security policies at the kernel level.
A good understanding of this threat model requires familiarity with Kubernetes architectural concepts, eBPF fundamentals, and [Tetragon's overall architecture]({{< ref "/docs/overview" >}}). The model addresses multiple deployment scenarios, including Kubernetes-based deployments using DaemonSets, standalone containerized agents, and systemd-managed service deployments on individual hosts.

{{< figure
    src="/images/smart_observability.png"
    caption="Tetragon Overview Diagram"
    width=800px
    alt="A diagram showing Tetragon capabilities and how it interacts with Kubernetes, the kernel and other metrics, logging, tracing or events systems"
>}}

This analysis evaluates threats associated with five distinct attacker profiles, each representing varying levels of access and privilege within the system. These profiles encompass attackers operating within Kubernetes workloads, individuals with limited host privileges, attackers with root-equivalent access, attackers who have compromised the Kubernetes API server, and network-based attackers capable of intercepting or manipulating network traffic.
The threat model assumes Tetragon operates on fully patched systems with appropriate security hardening, including [Kubernetes security best practices](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) where applicable. This baseline assumption enables a focus on threats specific to Tetragon’s design and operation, rather than general system vulnerabilities.

## Threat Surface Analysis

Tetragon supports multiple deployment architectures, each introducing a unique attack surface that must be evaluated as part of the overall security posture. In Kubernetes environments, Tetragon is deployed as a DaemonSet, ensuring that an agent runs on every node. Tetragon can also run as a standalone agent, either containerized or managed by systemd, offering flexibility for non-Kubernetes environments.
The Kubernetes DaemonSet deployment integrates deeply with the Kubernetes API and relies on it for policy distribution and management. This integration enables centralized control but also introduces dependencies on the security of the Kubernetes control plane. In contrast, standalone deployments necessitate alternative mechanisms for policy management and event collection, which may introduce vulnerabilities related to local file access and network communications.

## Tetragon Agent Architecture

The Tetragon agent is the primary component responsible for loading eBPF programs into the kernel, collecting events, and enforcing configured policies. Because of its privileged position within the system, the agent becomes a high-value target for attackers seeking to evade detection or manipulate security controls.

In Kubernetes deployments, configuration is primarily managed via two custom resource definitions (CRDs): [TracingPolicy]({{< ref "/docs/reference/tracing-policy/" >}}) and [TracingPolicyNamespaced]({{< ref "/docs/concepts/tracing-policy/k8s-filtering/#namespace-filtering" >}}).

These CRDs enable centralized policy management via the Kubernetes API but require strict RBAC to prevent unauthorized policy changes. In standalone deployments, configuration relies on YAML files stored directly on the host system, making security dependent on filesystem permissions and host access controls.

The agent can expose a gRPC endpoint that listeners may attach to. The gRPC endpoint can be configured to listen on either a Unix domain socket (UDS) or a local network port. The UDS approach generally provides better security isolation compared to network-based listening. However, both still require rigorous access control measures to prevent unauthorized interception of event streams.

[Event export]({{< ref "docs/concepts/events" >}}) mechanisms constitute a significant aspect of the agent's attack surface. Tetragon can emit events via multiple channels, including standard output streams for Kubernetes container logging, JSON log files, and gRPC streams over network ports. Each export method necessitates robust security controls to safeguard the confidentiality of event data, which may include sensitive information about system behavior and detected security incidents.
The Tetragon Prometheus metrics endpoint also introduces a potential vector for information disclosure. Although these metrics do not directly reveal security events, they can disclose details about Tetragon's configuration, performance characteristics, and operational state, which may assist attackers during reconnaissance.

## Tetragon Operator Component

The Tetragon Operator plays a vital role in Kubernetes-based deployments by managing the lifecycle of custom ResourceDefinitions. Its privileged access to the Kubernetes API server renders it a sensitive component from a security standpoint.

The following custom resources are registered by the Tetragon Operator:

- TracingPolicy
- TracingPolicyNamespaced
- PodInfo

The [PodInfo](https://github.com/cilium/tetragon/blob/main/operator/podinfo/podinfo_controller.go) CRD maintained by the operator functions as a key-value store mapping Pod IP addresses to workload objects, enabling Tetragon to attribute network activity and other events to specific Kubernetes resources. 

From an architectural security perspective, the operator's responsibility for distributing policies across the cluster implies that a compromise of the operator could facilitate cluster-wide policy manipulation. Recognizing this centralized control function is crucial for implementing effective protective measures and monitoring mechanisms.

## Threat Actor Profiles and Attack Scenarios

### Kubernetes Workload Attacker

{{< figure
    src="/images/threat-model/kubernetes-workload-attacker.png"
    caption="Kubernetes Workload Attacker Diagram"
    width=800px
    alt="A diagram showing Tetragon capabilities and how it interacts with Kubernetes, the kernel and other metrics, logging, tracing or events systems"
>}}

Consider an adversary who has compromised an application in the cluster and can execute arbitrary code in that container's context. Such scenarios typically result from vulnerabilities in exposed services, supply-chain compromises affecting container images, or the exploitation of application-level flaws. In this analysis, the attacker is assumed to operate without elevated Kubernetes privileges, without additional Linux capabilities beyond the container default set, and without direct access to host namespaces or filesystems.

In this context, the attacker's primary capability against Tetragon is to generate events that require processing, storage, and potential export by the monitoring infrastructure. By deliberately creating activities that maximize event volume, the attacker may attempt to overwhelm Tetragon's event processing pipeline, leading to event loss, performance degradation, or storage exhaustion. This denial-of-service attack vector exploits Tetragon's core requirement to observe and record security-relevant activities, thereby turning a fundamental strength into a potential vulnerability.

Current analysis indicates that such attackers cannot directly compromise Tetragon's integrity or availability beyond denial-of-service scenarios. The isolation enforced by container boundaries, together with Tetragon's operation at the kernel level, prevents workload-level attackers from manipulating Tetragon's eBPF programs, configuration, or core functionality. Nevertheless, the denial-of-service vector remains a significant concern that requires operational controls.

**Recommended controls**:

Proactive monitoring can mitigate workload-based denial-of-service attacks. Operators are encouraged to monitor and alert on dropped events via [Tetragon Health Metrics]({{< ref "/docs/installation/metrics/" >}}). Some relevant metrics include:

- tetragon_events_total
- tetragon_observer_ringbuf_events_lost_total
- tetragon_map_in_use_gauge
- tetragon_bpf_missed_events_total

The event throttling feature offers protection against event floods. This feature monitors event generation rates per cgroup and automatically restricts further event posting when configurable thresholds are surpassed. Upon activation, the system generates a THROTTLE_START event to inform operators of the condition. Operators should monitor these throttling events, as they may indicate ongoing attacks, though they can also result from legitimate high-activity workloads. Event throttling is applied uniformly across all workloads on a node, ensuring that no single workload monopolizes event-processing resources.


### Limited Privilege Host Attacker

{{< figure
    src="/images/threat-model/limited-host.png"
    caption="Limited Privilege Host Attacker Diagram"
    width=800px
    alt="A diagram showing Tetragon capabilities and how it interacts with Kubernetes, the kernel and other metrics, logging, tracing or events systems"
>}}

A limited-privilege host attacker can escalate beyond container boundaries and access host namespaces and resources, but lacks the root privileges required to manipulate kernel state or disable system services. Such scenarios may result from privilege escalation paths, including container escapes that yield non-privileged host access, compromise of services with elevated Linux capabilities, or exploitation of vulnerabilities that grant specific privileged operations without full root access.

The threats posed by a limited-privilege host attacker depend on the specific privileges and access they obtain.

- If the attacker can access the Tetragon Unix socket file at `/var/run/tetragon/tetragon.sock`, they can interact with Tetragon's gRPC API, enabling them to read and potentially modify current tracing policies. Such access undermines Tetragon's integrity by allowing the attacker to disable monitoring, adjust policies to evade detection, or inject policies that generate misleading events to confuse security teams. The default socket permissions of 0660 restrict access to the user and group running the Tetragon agent, assuming no other processes share those credentials.
- Deployments that expose the gRPC API on a network port, rather than a Unix socket, introduce additional risk. An attacker with network access to the node's localhost interface could connect to this port and obtain the same policy-manipulation capabilities as with Unix socket access, without requiring specific filesystem permissions. This expanded attack surface makes network-based gRPC exposure particularly risky and generally unsuitable for production environments unless robust authentication is implemented.
- In Kubernetes environments, policy manipulation can have consequences that extend beyond the initially compromised node. Since tracing policies may be distributed across the cluster via Custom Resource Definitions (CRDs), an attacker who can modify policies could affect monitoring and enforcement across the entire cluster. 
- Access to Tetragon's event export files is a significant threat vector for limited-privilege attackers. If an attacker can read the JSON files where Tetragon records security events, they obtain comprehensive insight into the security monitoring capabilities deployed on the node. This information reveals which activities are monitored, which processes are tracked, which file accesses are logged, and which network connections trigger alerts. With this knowledge, an attacker can adapt their behavior to avoid detection by selecting techniques that fall outside monitored activity patterns.

Tetragon's current design does not offer comprehensive protection against all forms of kernel-level exploitation. For example, an attacker who acquires the CAP_SYS_BPF capability can load arbitrary eBPF programs into the kernel. Although the eBPF verifier enforces security boundaries, historical evidence demonstrates that verifier bypasses are possible, potentially enabling malicious programs to compromise kernel integrity. Tetragon cannot prevent or mitigate such attacks when they succeed because the attacker operates at the same kernel level as Tetragon's monitoring infrastructure. This limitation is an inherent constraint of eBPF-based security tools within the standard Linux security model.

**Recommended controls:**

- Protective measures against limited-privilege host attackers should prioritize strong access controls and minimize the attack surface. 
- Containers must not run with the same user and group IDs as the Tetragon agent, thereby preventing access to the Unix socket through credential matching. The default Unix socket permissions should remain unchanged. 
- Users using network-based gRPC access should critically assess the need for this configuration and, if feasible, [transition to Unix socket-based access with appropriate filesystem permissions]({{< ref "/docs/reference/daemon-configuration/#restrict-grpc-api-access" >}}).
- Event log files require similarly strict permission management. The 0600(rw-------) permissions appropriately restrict access, and operators should resist any pressure to relax these restrictions even for operational convenience. If multiple processes need access to events, the preferred approach is to stream events over gRPC with appropriate access controls, rather than relying on lax filesystem permissions.

## Kubernetes API Server Attacker

{{< figure
    src="/images/threat-model/kubernetes-api.png"
    caption="Kubernetes API Server Attacker Diagram"
    width=800px
    alt="A diagram showing Tetragon capabilities and how it interacts with Kubernetes, the kernel and other metrics, logging, tracing or events systems"
>}}

An attacker who compromises the Kubernetes API server or acquires credentials for API access obtains substantial control over Tetragon's operations in Kubernetes-based deployments. The API server serves as the control plane for policy distribution, establishing a critical trust boundary within Tetragon's security model. As a result:

- An attacker with read access to Tetragon's CRDs can view the TracingPolicy deployed throughout the cluster. This level of visibility exposes the entire monitoring and enforcement posture, including the specific activities Tetragon observes, the policies enforcing security boundaries, and potential gaps in coverage. Knowledge of deployed policies enables sophisticated attackers to develop evasion strategies by selecting attack techniques that are not monitored or by exploiting edge cases in policy logic.
- Write access to policy CustomResourceDefinitions constitutes a significantly more severe compromise. An attacker with the ability to create, modify, or delete TracingPolicy can fundamentally alter Tetragon's behavior across the cluster. Such an attacker could remove existing policies to eliminate monitoring, create permissive policies that allow previously blocked operations, or introduce policies that generate false positive events to overwhelm security teams and obscure genuine attacks.

**Recommended controls:**

- The primary defense against API server attacks is the rigorous implementation of Kubernetes Role-Based Access Control (RBAC). RBAC policies should adhere to the principle of least privilege, granting access to Tetragon CustomResourceDefinitions only to users and service accounts with legitimate operational requirements. 
- Read access to policies should be limited to security and operations teams that require insight into the monitoring posture, while write access should be even more strictly controlled, potentially necessitating multi-person approval for modifications to critical policies.

## Root-Equivalent Host Attacker

{{< figure
    src="/images/threat-model/root.png"
    caption="Root-Equivalent Host Attacker Diagram"
    width=800px
    alt="A diagram showing Tetragon capabilities and how it interacts with Kubernetes, the kernel and other metrics, logging, tracing or events systems"
>}}

An attacker with root privileges on a host running Tetragon gains complete control of the system, rendering all local security controls ineffective. This scenario represents the worst-case outcome from a host security perspective, as no technical controls can reliably protect against a fully privileged adversary.
With root access, an attacker can fully manipulate the local Tetragon agent, including disabling it, altering its configuration to evade monitoring, or injecting false events into the event stream to mislead security teams. The eBPF programs that Tetragon uses for monitoring can be unloaded, replaced, or modified without restriction. Event export mechanisms may be redirected, disabled, or filtered to conceal malicious activity. Consequently, no security observability data from a root-compromised node can be considered trustworthy, as the attacker can manipulate all aspects of data collection and export.
Tetragon records credentials such as user IDs and Linux capabilities only at process creation (exec time) and solely for the main thread. As a result, credentials reported in Tetragon events reflect the state at process creation, not necessarily at the time of the event. A privileged attacker can exploit this by launching processes with benign credentials and subsequently using setuid, setgid, or capability manipulation system calls to escalate privileges. Events from such processes will appear to originate from unprivileged contexts, potentially misleading security analysts regarding the true nature of the activity.
The consequences of root compromise extend beyond the local node in Kubernetes environments. The service account token mounted in the Tetragon agent's container, or accessible through its execution context, provides authentication credentials for communicating with the Kubernetes API server. A root-level attacker can extract this token to query the API server, potentially enumerating deployed policies, examining configurations of other nodes, or collecting intelligence about the broader environment. The permissions assigned to this service account define the scope of possible API operations, but even read-only access can yield valuable reconnaissance information.

**Recommended control:**

The Tetragon Operator should not be deployed on nodes hosting untrusted workloads, as a compromised workload could compromise the operator if both share a node. Instead, the operator should be scheduled exclusively on control plane nodes using appropriate node selectors, taints, and tolerations. This scheduling constraint ensures that a compromised workload does not provide a pathway to operator compromise, thereby limiting an attacker's ability to exploit operator privileges for cluster-wide policy manipulation.

## Network Attacker

{{< figure
    src="/images/threat-model/kubernetes-network.png"
    caption="Network Attacker Diagram"
    width=800px
    alt="A diagram showing Tetragon capabilities and how it interacts with Kubernetes, the kernel and other metrics, logging, tracing or events systems"
>}}

A network attacker with man-in-the-middle capabilities can intercept, inspect, and potentially modify traffic between Tetragon components and external systems. This attacker profile is especially relevant in environments where Tetragon exports data across network boundaries or where monitoring infrastructure spans several network segments.
The Prometheus metrics endpoint exposed by Tetragon constitutes a potential vector for information disclosure. Although these metrics do not directly include security events or detailed observability data, they provide operational insights into Tetragon's performance, configuration, and state. A sophisticated attacker could analyze these metrics over time to infer policy changes, identify periods of high activity that may conceal attack traffic, or assess the monitoring system's capacity limits to plan denial-of-service attacks.
More significant concerns arise regarding the risks of exporting security events. If Tetragon transmits events to external collectors, SIEM platforms, or object storage systems without encryption in transit, a network attacker can intercept these event streams and obtain comprehensive insight into security monitoring. This access reveals monitored activities, policy enforcement decisions, detected anomalies, and incident response patterns. With this intelligence, attackers can analyze the security posture in detail, identify blind spots, evade detection patterns, and time attacks to exploit operational conditions that may reduce detection likelihood and integrity risks.

**Recommended controls:**

- Protection against network attackers requires implementing encryption in transit for all data exported from Tetragon. Security event collection should use HTTPS or other encrypted protocols when transmitting data to external storage, SIEM platforms, or analysis systems. The specific implementation depends on the chosen event export mechanism, but all network-based exports should use strong encryption with proper certificate validation to prevent man-in-the-middle attacks.
- Prometheus metrics collection also benefits from encryption. Enabling TLS on the Prometheus metrics endpoint prevents casual interception of operational metrics, and configuring Prometheus scrapers to use authenticated TLS connections ensures both confidentiality and authenticity of the metrics channel. Users should weigh the operational overhead of managing TLS certificates for metrics collection against the risks associated with metrics disclosure in their specific threat model.


## Operational Security Considerations

- Beyond the specific attacker profiles discussed above, effective operation of Tetragon in production environments also requires attention to several cross-cutting security concerns. Security events often contain sensitive information about system behavior, user activities, process execution patterns, and network communications. This data needs protection from unauthorized disclosure through appropriate access controls on storage systems, encryption in transit and at rest, and careful consideration of data retention and destruction policies. Organizations subject to regulatory requirements should consider how Tetragon event data intersects with those requirements.

- Policy management is critical because policies determine what Tetragon monitors and enforces. Change control processes should govern policy updates, ensuring that modifications are reviewed, tested in non-production environments, and approved before deployment. Policy validation mechanisms can identify common errors such as syntax issues or references to nonexistent resources, but comprehensive validation of policy logic and effectiveness requires testing against representative workloads. Users should maintain thorough policy documentation that explains each policy's intent and expected behavior to facilitate review and troubleshooting.

- Tetragon generates events that can be incorporated into existing incident response workflows, SIEM platforms, and security analytics tools. The volume, format, and semantic content of these events influence the success of integration. Users should implement appropriate event filtering, aggregation, and enrichment to ensure Tetragon data is actionable within their operational context. Excessive false positives can lead to alert fatigue and undermine security effectiveness, highlighting the importance of tuning and validating detection rules.

## Conclusion

While eBPF provides unparalleled visibility and enforcement capabilities, its security is still tied to the integrity of  the adjacent environment it operates in, particularly the host operating system and the Kubernetes control plane. Implementing mitigation strategies that encompass the recommended controls in this threat model will ensure Tetragon continues to remain a trusted source of truth. The table below summarizes the attacker profiles, primary vectors, severity, and the primary mitigation.

| Attacker Profile | Primary Vector | Impact Severity | Primary Mitigation |
| :--- | :--- | :--- | :--- |
| Workload | Event Flooding | Medium (DoS) | Event Throttling / Rate Limiting |
| Host (Limited) | Socket/File Access | High (Tampering) | Strict RBAC / Socket Permissions |
| API Server | CRD Modification | Critical (Global) | Kubernetes RBAC & Admission Controllers |
| Network | MitM / Interception | Low/Med (Info Leak) | TLS / mTLS for gRPC & Prometheus |

## Feedback and Responsible Disclosure

As Tetragon evolves, new features and capabilities may expand the attack surface or alter the threat landscape. Users should remain informed about Tetragon security updates, engage with the community to exchange threat intelligence and defensive strategies, and periodically reassess their deployments in light of emerging threats.
The Tetragon community encourages feedback on this threat model and invites users to report any threats not addressed in this analysis. Security concerns should be communicated to the private security mailing list at [security@cilium.io](mailto:security@cilium.io) in accordance with responsible disclosure practices. 

