---
title: "Real-Time Privileges Monitoring with Tetragon"
description: "Monitor credential changes at the kernel level to detect suspicious activity and safeguard system integrity."
layout: "features"
body_class: "td-home"

hero:
  title: "Privileges Monitoring"
  intro: "Tetragon is a security tool that provides comprehensive process monitoring capabilities, offering detailed visibility into process behavior and execution within Kubernetes environments⁠"
  videoID: "2BIe4VmSYyQ"

contentTitle: "Understanding Process Behavior in Complex Environments"

features:
  - title: "Real-Time Credential Monitoring"
    description: "Track changes to user IDs, group IDs, and capabilities as they occur, ensuring immediate visibility."
    icon: "monitoring"
  - title: "CSystem Call and Kernel-Level Insights"
    description: "Hook into system calls to capture detailed information on credential manipulations in real-time."
    icon: "search-activity-blue"
  - title: "Tamper-Resistant Observability"
    description: "Ensure reliable detection of credential changes with kernel-layer integration and execution context tracking."
    icon: "telescope-green"
  - title: "Suspicious Activity Detection"
    description: "Identify unauthorized privilege changes across Kubernetes clusters and Linux environments to prevent system compromises."
    icon: "target-blue"
---

In Linux environments, processes have various credentials—such as user and group IDs, capabilities, and security flags—that define their privileges. Threat actors frequently exploit these credentials to escalate privileges or circumvent security controls. Without real-time visibility into these changes, security teams are left blind to critical signs of compromise.

Tetragon addresses this challenge by providing real-time monitoring of process credentials at both the system call and kernel levels. By hooking into system calls that manipulate credentials, Tetragon can capture detailed information about which processes or containers are attempting to change user IDs, group IDs, or capabilities. Tetragon kernel-layer integration offers enhanced reliability by capturing full credential changes within their execution context, ensuring tamper-resistant insights. This allows security teams to quickly identify suspicious privilege changes across Kubernetes clusters and Linux environments, providing critical observability into credential manipulations that could compromise system integrity.
