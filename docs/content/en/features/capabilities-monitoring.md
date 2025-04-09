---
title: "Real-Time Privilege Monitoring with Tetragon"
description: "Track Linux capability checks and privileged operations in Kubernetes for precise control and enhanced security."
layout: "features"
body_class: "td-home"

hero:
  title: "Capabilities Monitoring"
  intro: "Tetragon is a security tool that provides comprehensive process monitoring capabilities, offering detailed visibility into process behavior and execution within Kubernetes environments⁠"
  videoID: "WZXC5MLo7HI"

contentTitle: "Understanding Process Behavior in Complex Environments"

features:
  - title: "Real-Time Privilege Monitoring"
    description: "Observe and record Linux capability checks in real time, gaining visibility into privileged operations."
    icon: "monitoring"
  - title: "Context-Rich Capability Insights"
    description: "Capture metadata such as requested capabilities, process identity, and access verdicts for precise analysis."
    icon: "search-activity-blue"
  - title: "Enhanced Kubernetes Security"
    description: "Fine-tune security contexts for pods and containers by identifying unnecessary privileges and misconfigurations."
    icon: "shield-lock-green"
  - title: "Proactive Privilege Management"
    description: "Reduce risks by understanding and managing the exact capabilities required by workloads in Kubernetes environments."
    icon: "management"
---

Processes running with high privileges or elevated capabilities can pose security risks, as they may bypass critical security controls or perform unauthorized actions. For example, misconfigured Kubernetes workloads might unintentionally request overly broad privileges, increasing the risk of exploitation. Identifying which processes are using elevated privileges and understanding the capabilities they require is essential for maintaining a secure environment. Security teams often struggle to identify and manage the precise capabilities required by applications running in Kubernetes environments and Linux capabilities are often granted too broadly due to a lack of visibility into what each workload truly needs.

Tetragon empowers security teams to observe and record Linux capability checks in real time, providing deep visibility into the privileged operations performed within Kubernetes environments. When the kernel evaluates whether a process can perform a privileged action, Tetragon captures these events, recording metadata such as the requested capability, the process identity, and the verdict—whether access was granted or denied. This comprehensive data helps teams understand the precise capabilities in use, enabling fine-tuned control over security contexts for pods and containers and ​​helping teams identify unnecessary privileges and tighten security configurations across Kubernetes clusters.
