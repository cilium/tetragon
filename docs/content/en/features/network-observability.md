---
title: "Enhanced Network Observability with Tetragon"
description: "Link network events to processes and workloads with Kubernetes-aware insights for better security and troubleshooting."
layout: "features"
body_class: "td-home"

hero:
  title: "Network Observability"
  intro: "Tetragon network observability provides deep insights into network events such as network connections made by processes."
  videoID: "CiNnro9o-LM"

contentTitle: "Network Observability for Cloud Native Environments"

features:
  - title: "Process-Aware Network Monitoring"
    description: "Link every network event to the specific processes and workloads driving the activity for full context."
    icon: "monitoring"
  - title: "Socket Lifecycle Insights"
    description: "Track the entire lifecycle of sockets, including connections, sent/received bytes, and socket events."
    icon: "socket-plug"
  - title: "Kubernetes-Enriched Metadata"
    description: "Enhance network observability with Kubernetes identities, including pod labels and namespaces."
    icon: "table"
  - title: "Comprehensive Network Visibility"
    description: "Gain a holistic view of network activity to enable faster troubleshooting and stronger security across cloud-native environments."
    icon: "eye"
---

In cloud native environments, network monitoring is essential but often disconnected from the processes and workloads driving the activity. Traditional observability typically stop at capturing connections, leaving questions about which processes initiated them or how they interact with other workloads and endpoints unanswered. This lack of context makes anomaly detection and root-cause analysis difficult.

Tetragon brings clarity to network observability by directly linking every network event to the specific processes and workloads behind them. It provides detailed insights into the entire socket lifecycle, recording connections to local or external endpoints, tracking sent and received bytes, and capturing socket events with enriched Kubernetes metadata. By tracing the full lifecycle of network sockets linked with Kubernetes identities, Tetragon offers a comprehensive view of network activity across your environment. These actionable insights empower faster troubleshooting and a stronger security posture, all within a lightweight and scalable solution.
