---
title: "Kubernetes Identity Aware Policies with Tetragon"
description: "Enforce precise, workload-specific policies in Kubernetes with eBPF-powered observability and runtime control."
layout: "features"
body_class: "td-home"

hero:
  title: "Kubernetes Identity Aware Policies"
  intro: "Tetragon was built from the ground up to cater to the unique needs of Linux, container, and Kubernetes workloads⁠"
  videoID: "3sRJk7CgMyU"

contentTitle: "Kubernetes-Aware Security Observability and Runtime Enforcement"

tagline: "Enforce precise, workload-specific policies in Kubernetes with eBPF-powered observability and runtime control."

features:
  - title: "Kubernetes Identity Aware Policies"
    description: "Leverage in-kernel filtering to enforce policies based on Kubernetes constructs like namespaces, pod labels, and container fields."
    icon: "gear"
  - title: "Precise Workload Control"
    description: "Focus monitoring and enforcement on specific workloads or high-risk namespaces to reduce noise and overhead."
    icon: "monitor"
  - title: "Dynamic Policy Enforcement"
    description: "Adapt to the dynamic, ephemeral nature of Kubernetes environments with policies tailored to changing workloads."
    icon: "shield-code"
  - title: "Broad Kubernetes Runtime Support"
    description: "Supports both containerd and CRI-O, bringing runtime security to diverse Kubernetes environments."
    icon: "telescope-blue"
---

In traditional security environments, policies are often applied uniformly, assuming static infrastructure. This approach is ill-suited to Kubernetes clusters, where workloads are dynamic, ephemeral, and highly diverse. This complexity brings the need for security teams to enforce policies with precision. Enforcing policies too broadly may lead to excessive noise or performance overhead, while enforcing too narrowly can result in missing critical events.

Tetragon addresses these challenges with Kubernetes Identity Aware Policies, leveraging eBPF for in-kernel filtering based on Kubernetes constructs like namespaces, pod labels, and container fields. Tetragon Kubernetes identity aware policies enable security teams to precisely control which workload(s) are monitored or constrained. Kubernetes identity aware policies equip teams with the precision to apply Tetragon’s security observability and runtime enforcement only where needed, such as focusing observability on high-risk namespaces or critical workloads.
