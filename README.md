<a href="https://tetragon.cilium.io">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/cilium/tetragon/releases/download/tetragon-cli/logo.png" width="400">
    <img src="https://github.com/cilium/tetragon/releases/download/tetragon-cli/logo-dark.png" width="400">
  </picture>
</a>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

Cilium’s new [Tetragon](https://tetragon.cilium.io) component enables powerful
real-time, eBPF-based Security Observability and Runtime Enforcement.

Tetragon detects and is able to react to security-significant events, such as

- Process execution events
- System call activity
- I/O activity including network & file access

When used in a Kubernetes environment, Tetragon is Kubernetes-aware - that is,
it understands Kubernetes identities such as namespaces, pods and so on - so
that security event detection can be configured in relation to individual
workloads.

[![Tetragon Overview Diagram](https://github.com/cilium/tetragon/blob/main/docs/static/images/smart_observability.png)](https://tetragon.cilium.io/docs/overview/)

See more about [how Tetragon is using eBPF](https://tetragon.cilium.io/docs/overview#functionality-overview).

## Getting started

Refer to the [official documentation of Tetragon](https://tetragon.cilium.io/docs/).

To get started with Tetragon, take a look at the [getting started
guides](https://tetragon.cilium.io/docs/getting-started/) to:
- [Try Tetragon on Kubernetes](https://tetragon.cilium.io/docs/getting-started/kubernetes-quickstart-guide/)
- [Try Tetragon on Linux](https://tetragon.cilium.io/docs/getting-started/try-tetragon-linux/)
- [Deploy Tetragon](https://tetragon.cilium.io/docs/getting-started/deployment/)
- [Install the Tetra CLI](https://tetragon.cilium.io/docs/getting-started/install-tetra-cli/)

Tetragon is able to observe critical hooks in the kernel through its sensors
and generates events enriched with Linux and Kubernetes metadata:
1. **Process lifecycle**: generating `process_exec` and `process_exit` events
   by default, enabling full process lifecycle observability. Learn more about
   these events on the [process lifecycle use case page](https://tetragon.cilium.io/docs/use-cases/process-lifecycle/).
1. **Generic tracing**: generating `process_kprobe`, `process_tracepoint` and
   `process_uprobe` events for more advanced and custom use cases. Learn more
   about these events on the [TracingPolicy concept page](https://tetragon.cilium.io/docs/concepts/tracing-policy/)
   and discover [multiple use cases](https://tetragon.cilium.io/docs/use-cases/) like:
   - [🌏 network observability](https://tetragon.cilium.io/docs/use-cases/network-observability/)
   - [📂 file access](https://tetragon.cilium.io/docs/use-cases/file-access/)
   - [🔑 credentials monitoring](https://tetragon.cilium.io/docs/use-cases/linux-process-credentials/)
   - [🔓 privileged execution](https://tetragon.cilium.io/docs/use-cases/process-lifecycle/privileged-execution/)

See further resources:
- [Conference Talks, Books, Blog Posts, and Labs](https://tetragon.cilium.io/docs/resources/)
- [Frequently Asked Question](https://tetragon.cilium.io/docs/faq/)
- [Step by steps tutorials](https://tetragon.cilium.io/docs/tutorials/)
- [References](https://tetragon.cilium.io/docs/reference/)

## Join the community

Join the Tetragon [Slack channel](https://cilium.herokuapp.com/) to chat with
developers, maintainers, and other users. This is a good first stop to ask
questions and share your experiences.

## How to Contribute

For getting started with local development, you can refer to the
[Contribution Guide](https://tetragon.cilium.io/docs/contribution-guide/). If
you plan to submit a PR, please ["sign-off"](https://tetragon.cilium.io/docs/contribution-guide/developer-certificate-of-origin/)
your commits.

